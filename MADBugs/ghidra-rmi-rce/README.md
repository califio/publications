# Ghidra Client RCE via Unfiltered RMI Deserialisation

### Summary

An unsafe-deserialisation vulnerability in Ghidra's client-side Shared-Project connection code allows any attacker who can hand a victim a Ghidra project file to achieve unauthenticated remote code execution on the victim's workstation. The victim's only required action is **File → Open Project**.

The client issues RMI calls against a Ghidra Server and deserialises the returned objects via `ObjectInputStream.readObject()` with no `ObjectInputFilter` in effect. The server installs a strict allow-list filter at start-up; the equivalent call is never made on the client. The first RMI call — `reg.list()`, performed before any authentication callback is exchanged — is sufficient to reach the sink. A deserialisation gadget that reaches `Runtime.getRuntime().exec(…)` exists using only classes from `jython-standalone-2.7.4.jar`, which ships on the default Ghidra client classpath.

The connection itself does not require a user-typed URL. `DefaultProject.restore()` silently opens a `ghidra://` connection for every `<OPEN_REPOSITORY_VIEW URL="…"/>` element it finds in a project's `projectState` XML file — so merely opening a locally-stored project the attacker prepared is enough to reach the sink.

Confirmed against Ghidra master HEAD [`91a2691`](https://github.com/NationalSecurityAgency/ghidra/commit/91a269103fe5d133c14ec3afa60280dccb94be5c) (2026-04-06, builds as 12.2_DEV) running on Eclipse Temurin 21.0.10. The code paths involved are unchanged in every release containing the Shared Project feature (≥ 9.1).

### Details

The vulnerability has two parts in Ghidra's own code, plus one gadget contribution from the bundled Jython 2.7.4 jar. Each part is independently patchable.

### 1. Client RMI deserialisation is unfiltered

[`Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/client/ServerConnectTask.java:155-206`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/client/ServerConnectTask.java#L155-L206) — the first RMI interaction the client performs:

```java
Registry reg = LocateRegistry.getRegistry(server.getServerName(),
    server.getPortNumber(), new SslRMIClientSocketFactory());
checkServerBindNames(reg);                                                    // → reg.list()
gsh = (GhidraServerHandle) reg.lookup(GhidraServerHandle.BIND_NAME);          // → reg.lookup()
gsh.checkCompatibility(GhidraServerHandle.MINIMUM_INTERFACE_VERSION);
```

`checkServerBindNames` at [`:423-462`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Framework/FileSystem/src/main/java/ghidra/framework/client/ServerConnectTask.java#L423-L462) invokes `reg.list()`. The JDK routes that through `sun.rmi.registry.RegistryImpl_Stub.list`, which reads the server response with a `MarshalInputStream` (subclass of `ObjectInputStream`) and calls `in.readObject()` before casting to `String[]` — all `readObject`/`readResolve` side-effects run before the cast.

Compare the server-side symmetry at [`Ghidra/Features/GhidraServer/src/main/java/ghidra/server/remote/GhidraServer.java:917-979`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Features/GhidraServer/src/main/java/ghidra/server/remote/GhidraServer.java#L917-L979):

```java
ObjectInputFilter patternFilter = readSerialFilterPatternFile();
ObjectInputFilter filter = new ObjectInputFilter() {
    @Override public Status checkInput(FilterInfo info) { … }
};
ObjectInputFilter.Config.setSerialFilter(filter);
```

backed by the allow-list in `Ghidra/Features/GhidraServer/data/serial.filter`.

In contrast, there is no process-wide filter on the client, so every RMI return value (`reg.list`, `reg.lookup`, `getAuthenticationCallbacks`, every `RepositoryServerHandle` method) is deserialised unrestricted.

### 2. `DefaultProject.restore()` auto-connects to untrusted URLs

[`Ghidra/Framework/Project/src/main/java/ghidra/framework/project/DefaultProject.java:487-499`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Framework/Project/src/main/java/ghidra/framework/project/DefaultProject.java#L487-L499) — executed whenever a project is opened with `doRestore=true` (GUI File → Open Project via [`GhidraRun.java:255`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Features/Base/src/main/java/ghidra/GhidraRun.java#L255), headless, or auto-open-last-project):

```java
it = root.getChildren(OPEN_REPOSITORY_VIEW_XML_NAME).iterator();
while (it.hasNext()) {
    Element elem = (Element) it.next();
    String urlStr = elem.getAttributeValue("URL");
    URL url = GhidraURL.toURL(urlStr);
    try {
        addProjectView(url, true);
    } catch (IOException e) { … }
}
```

The `<OPEN_REPOSITORY_VIEW URL="…">` elements come verbatim from the project's `projectState` XML file on disk. The code makes no distinction between URLs the user typed themselves and URLs that arrived inside a `projectState` file. No confirmation is shown, the URL is not displayed before connecting. For each element, `addProjectView` → `openProjectView` ([`DefaultProject.java:253-278`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Framework/Project/src/main/java/ghidra/framework/project/DefaultProject.java#L253-L278)) → `GhidraURLConnection.connect()` → `ServerConnectTask` — reaching the sink above.

### 3. Gadget on the client classpath — Jython 2.7.4

`Ghidra/Features/Jython/lib/jython-standalone-2.7.4.jar` is on every client classpath. Jython 2.7.4 patched the classic ysoserial `Jython1` chain by adding `readResolve() { throw new UnsupportedOperationException(); }` to `org.python.core.PyFunction`. The fix assumes `PyFunction` is the only serialisable `InvocationHandler` in Jython. It is not.

`org.python.core.PyMethod` is also `Serializable` (via `PyObject`), also implements `java.lang.reflect.InvocationHandler`, and has **no `readResolve` guard**:

```
$ javap -p org/python/core/PyMethod.class | head -2
public class org.python.core.PyMethod extends org.python.core.PyObject
    implements java.lang.reflect.InvocationHandler, org.python.core.Traverseproc

$ javap -p org/python/core/PyMethod.class | grep readResolve
(nothing)
```

`PyMethod.invoke(proxy, method, args)` routes into `__call__(Py.javas2pys(args))`, which delegates to `__func__.__call__(self, args, keywords)`. Pointing `__func__` at `org.python.core.BuiltinFunctions` — the package-private concrete subclass of `PyBuiltinFunctionSet` that backs `__builtin__`, whose `__call__` `tableswitch`es on the `index` field with `index=18` dispatching to `__builtin__.eval` — gives a serialisable reference to `eval`. `eval(code, globals, locals)` accepts a `PyCode`. `PyBytecode`, a `PyCode` subclass that implements a CPython 2.7 opcode interpreter, serialises cleanly (unlike Jython's JVM-compiled `PyTableCode`).

The bytecode payload is 21 bytes and references `java.lang.Runtime` as a `co_consts` entry; the resulting interpreter call is `Runtime.getRuntime().exec({"/bin/sh", "-c", CMD})`.

The full chain on the wire:

```
java.util.PriorityQueue.readObject
  └─ heapify → siftDownUsingComparator
    └─ Proxy(Comparator).compare(globals, locals)
      └─ org.python.core.PyMethod.invoke(…)
        └─ PyMethod.__call__([g, l])
          └─ BuiltinFunctions(index=18).__call__(PyBytecode, g, l)
            └─ __builtin__.eval(PyBytecode, g, l)
              └─ Py.runCode → PyBytecode interpreter
                └─ Runtime.getRuntime().exec({"/bin/sh","-c",CMD})
```

Closing (1) or (3) alone stops the RCE; closing (2) stops the file-based delivery but leaves the same sink reachable for any other `ghidra://` URL the user opens (GhidraGo protocol handler, `analyzeHeadless ghidra://host/x`, File → New Project → Shared Project, etc.).

### PoC

We are withholding the proof-of-concept (the `PyMethod` gadget builder, the SSL-wrapped JRMP responder, and the `Pwn.zip` generator) until a fixed Ghidra release is generally available. It will be published in this directory when the embargo lifts.

The observed victim stack trace — captured from `analyzeHeadless` running the same code path as `GhidraRun` — is included here so defenders can build detections in the meantime:

```
java.lang.ClassCastException: class org.python.core.PySingleton cannot be cast to class java.lang.Integer
    at java.rmi/sun.rmi.registry.RegistryImpl_Stub.list(RegistryImpl_Stub.java:95)
    at ghidra.framework.client.ServerConnectTask.checkServerBindNames(ServerConnectTask.java:430)
    at ghidra.framework.client.ServerConnectTask.getGhidraServerHandle(ServerConnectTask.java:173)
    at ghidra.framework.client.ServerConnectTask.run(ServerConnectTask.java:80)
    at ghidra.framework.project.DefaultProject.openProjectView(DefaultProject.java:259)
    at ghidra.framework.project.DefaultProject.addProjectView(DefaultProject.java:297)
    at ghidra.framework.project.DefaultProject.restore(DefaultProject.java:493)
    at ghidra.framework.project.DefaultProjectManager.openProject(DefaultProjectManager.java:134)
```

### Test environment

| | |
|---|---|
| Ghidra (source) | master @ [`91a2691`](https://github.com/NationalSecurityAgency/ghidra/commit/91a269103fe5d133c14ec3afa60280dccb94be5c) (2026-04-06) |
| Ghidra (distribution) | `ghidra_12.2_DEV_20260408_mac_arm_64.zip` |
| Jython (client classpath) | `jython-standalone-2.7.4` |
| Victim JVM | Eclipse Temurin OpenJDK `21.0.10+7-LTS` (Homebrew) |
| Attacker JVM | Eclipse Temurin OpenJDK `21.0.10+7-LTS` (Docker) |
| Victim config | default — `ghidra.cacerts` unset, `jdk.serialFilter` unset, no application filter |
| Attacker cert | self-signed RSA-2048, SAN `DNS:evilserver,DNS:localhost,IP:127.0.0.1` |
| Host | macOS 25.4.0 (Darwin arm64), Docker 28.x |

### Impact

**Vulnerability type**: unauthenticated, pre-any-credential-handshake Java-deserialisation RCE on the Ghidra client, delivered via a locally-opened project file.

**Affected**: every Ghidra installation that has the `ghidra://` URL handler and the Shared Project feature compiled in — i.e. every standard release since 9.1, on Linux / macOS / Windows. No configuration option disables the vulnerable code paths.

**Attacker profile**: anyone who can hand the victim a file. The project bundle is plain-text metadata plus an empty DB skeleton — no executable content, no code, no binary; static scanners and email gateways see a small directory of XML. Realistic delivery channels include email attachment, Slack / Teams DM, AirDrop, shared cloud drives, `git clone`, GitHub "Download ZIP", and sample-sharing forums or mailing lists where "the Ghidra project of sample X" is the normal exchange format for reverse-engineering work.

**Required user action**: one click — `File → Open Project` or double-clicking the `.gpr` marker. No further prompts on the happy path, no credential entry, no server dialog, no URL displayed before the outbound connection goes out.

### Suggested fix

Three independently-effective changes. Either of the Ghidra-side fixes blocks the vulnerability on its own; the Jython fix is useful upstream.

1. **Install a client-side `ObjectInputFilter`.** Mirror the server-side allow-list already shipped at [`Ghidra/Features/GhidraServer/data/serial.filter`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Features/GhidraServer/data/serial.filter) on the client. The simplest form installs a `java.io.ObjectInputFilter.Config.setSerialFilterFactory` during bootstrap that attaches a restrictive allow-list only to streams constructed inside the RMI transport (`sun.rmi.*`), leaving unrelated uses of Java serialization in the client (tool state, `ObjectPropertyMapDB`, `GProperties`, `ObjectStorageStreamAdapter`, debugger-trace data, packed databases) untouched. This fixes the root cause — closing the sink regardless of how a `ghidra://` URL is reached (GUI File → Open Project, GhidraGo protocol handler, `analyzeHeadless ghidra://host/x`, File → New Project → Shared Project).

2. **Require user consent before following a `ghidra://` URL from `projectState`.** `DefaultProject.restore()` at [`DefaultProject.java:493`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Framework/Project/src/main/java/ghidra/framework/project/DefaultProject.java#L493) should not silently call `addProjectView(url, true)` with URLs sourced from a project file; surface the URL to the user and remember decisions per host. Closely related: the `OWNER`-absent default at [`DefaultProjectData.java:307`](https://github.com/NationalSecurityAgency/ghidra/blob/91a269103fe5d133c14ec3afa60280dccb94be5c/Ghidra/Framework/data/DefaultProjectData.java#L307) silently binds ownership of an externally-supplied project to the current user; this is what makes the PoC untargeted. Missing `OWNER` should be handled as "not created by this installation" rather than auto-claimed.

3. **Upstream Jython: add a `readResolve` guard to `PyMethod`** equivalent to the one already on `PyFunction`, and audit the other `Serializable` `PyObject` subclasses that implement `InvocationHandler` or transitively route `__call__` into `__builtin__` dispatch (`PyBuiltinFunctionSet` subclasses, `PyClassMethod`, `PyStaticMethod`, `PyCompoundCallable`, `PyReflectedFunction`).

### Disclosure Timeline

- 2026-04-16: Bug confirmed and reported to NSA Ghidra team
- 2026-04-21: Details published as part of MAD Bugs

## A note on the artifacts

The write-ups and PoCs in this series are AI-generated and human-verified. We keep human editing to a minimum so the artifacts document the current state of the art, which means we don't edit out hallucinations or slop. We do verify that the PoCs work. The blog posts are written by humans.
