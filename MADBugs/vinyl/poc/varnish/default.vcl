vcl 4.1;

# Completely stock VCL — only the backend is declared. No `sub vcl_recv`,
# no normalisation, no filters. The exploit works against the shipped
# builtin.vcl without a single custom VCL line.
backend default {
    .host = "record-store";
    .port = "8000";
    .first_byte_timeout = 30s;
    .between_bytes_timeout = 10s;
}
