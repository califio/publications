/*-----------------------------------------------------------------------------*/
/* Including Files                                                             */
/*-----------------------------------------------------------------------------*/
#include <vos/linux/types.h>
#include <vos/linux/interrupt.h>
#include <vos/linux/mm.h>
#include <vos/linux/dma-mapping.h>
#include <vos/linux/pagemap.h>
#include <vos/linux/init.h>
#include <vos/linux/module.h>
#include <vos/linux/fs.h> // struct file_operations
#include <vos/linux/cdev.h> // struct cdev and related APIs
#include <vos/linux/kdev_t.h>
#include <vos/linux/ioctl.h>

#if defined(KER_OS_ECOS)
#include <vos/linux/uaccess.h>          /*! copy_from_user, copy_to_user */
#include <vos/asm/getorder.h>
#include <vos/linux/gfp.h>
#include <vos/linux/mm_types.h>
#else
#include <vos/asm/uaccess.h>          /*! copy_from_user, copy_to_user */
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
#include <linux/of_irq.h>
#include <linux/cpumask.h>// for irq_affinity
#endif

#include "drv_dbg.h"
//#include "def_type.h"

//#include "ntirq.h"
#include "ker_reg.h"
#include "ker_hdma.h"
#include "priv_ker_hdma.h"
#include "hdma_driver.c"
#include "ker_syscalls.h"
#include "ker_common.h"

#if (HDMA_SUPPORT_SUSPEND_MODE == ENABLE)
#include "ker_pmi.h"
#include <vos/linux/mutex.h>	/* mutex_lock_ API */
#endif

#include "priv_ker_leon.h"

#include "ker_clk.h"

/*-----------------------------------------------------------------------------*/
/* Local Constant Definitions                                                  */
/*-----------------------------------------------------------------------------*/
// Enable KER_HDMA self-test or not
#define KER_HDMA_TEST TRUE

#if 0
#define KER_SUPPORT_LEON_FILL_GAMA
#endif

#define FPGA_TEST
#define PQ_658		//658, 563
#define OSD_REG_BASE 	(0xFC0D0000)

#ifdef FPGA_TEST
#define IMVQ_SRAM_BASE 	(0xFf000000)
#define IMVQ_SRAM_CTRL 	(0xFf002000)
#else
#define IMVQ_SRAM_BASE 	(0xFC130000)
#define IMVQ_SRAM_CTRL 	(0xFD110820)
#endif

#define PQ_SRAM_ENABLE  	(0xFE005AC0)
#define PQ_SRAM_DATA_PORT 	(0xFE005AE4)
#define PQ_SRAM_INDEX_PORT 	(0xFE005AE0)
#ifdef PQ_658
#define PQ_658_SRAM_CTRL	(0xFE005AE8)
#define PQ_658_SRAM_READ_DATA_PORT	(0xFE005AEC)
#endif

#define STR_DBG_TRIGGER_MODE_CHOOSE "Trigger mode? 0-Immediately, 1-H line count"
#define STR_DGB_TEST_COUNT "Test count? 0-Infinite or user define"
#define STR_DGB_TEST_ADDR_DATA_PATTERN "Test AHB devide? 0: IMVQ SRAM, 1: PQ IGAMMA"

#ifndef HDMA_REG_MENU
#define HDMA_REG_MENU (ENABLE)
#endif

/*-----------------------------------------------------------------------------*/
/* Local Types Declarations                                                    */
/*-----------------------------------------------------------------------------*/
struct hdma_device {
	struct cdev cdev;
    struct class *hdma_class;
};

/*-----------------------------------------------------------------------------*/
/* Extern Global Variables                                                     */
/*-----------------------------------------------------------------------------*/
#ifdef CFG_DYNAMIC_ALLOC_DEV_NUM
int hdma_major = 0;
#else
//int hdma_major = NTKHDMA_MAJOR;
int hdma_major = 210;
#endif

static struct hdma_device hdmadevice;

/*-----------------------------------------------------------------------------*/
/* Extern Function Prototype                                                   */
/*-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------*/
/* Local Function Prototype                                                    */
/*-----------------------------------------------------------------------------*/
#if( KER_HDMA_TEST )
static int _hdmaMmap( struct vos_file *pstFile, struct vm_area_struct *pstVma );
#endif

static long _hdmaIoctl( struct vos_file *pstFile, unsigned int u32Cmd, unsigned long u32Arg );
static int _hdmaFillPhys( void );

#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 21))
static irqreturn_t _hdmaInterruptHandler( int irq, void *dev_id );
#else
static irqreturn_t _hdmaInterruptHandler( int irq, void *dev_id, struct pt_regs *regs );
#endif

#if (HDMA_SUPPORT_SUSPEND_MODE)
static void _ker_hdma_pm_init_p (void);
static int _ker_hdma_suspend_p (struct device *dev);
static int _ker_hdma_resume_p (struct device *dev);

#if (KER_PMI_CENTER == 0)
static int _ker_hdma_pmi_p (struct device *pstDevice) ;
#endif

#endif


/*-----------------------------------------------------------------------------*/
/* Local Global Variables                                                      */
/*-----------------------------------------------------------------------------*/
static bool  g_b8HDMAInit = FALSE;
static const struct file_operations gstHDMAOps = {
    .owner = VK_THIS_MODULE,
    .unlocked_ioctl = _hdmaIoctl,
#if( KER_HDMA_TEST )
    .mmap = _hdmaMmap
#endif
};

#if( KER_HDMA_TEST )
static u32 gu32HDMAMemPhysAddr = 0;
static void *gpu32HDMAMemVirtAddr = NULL;
static u32 gu32HDMAMemSize = 1024 << 5; // 32KB
dma_addr_t dma_handle;
#endif

static ST_KER_HDMA_DRIVER *gpstDriver;

#if (HDMA_SUPPORT_SUSPEND_MODE)
static struct mutex gstHDMA_HW_Exexuting_Mutex;

static bool gbTestAllEnable = FALSE;

static const struct dev_pm_ops _ker_hdma_pm_ops = {
	.resume = _ker_hdma_resume_p,
	.suspend = _ker_hdma_suspend_p,
};

static struct bus_type _ker_hdma_bus = {    
	.name	= "khdma", 
	.pm		= &_ker_hdma_pm_ops,
};

struct device _ker_hdma_dev = {    
	.bus = &_ker_hdma_bus,
};

static ST_KER_HDMA_PARAMS st_HDMA_Suspend_HW_PAR;


#if (KER_PMI_CENTER == 0)
static KER_PMI_CMD_en			genHdmaPMICmdStatus;
#endif

#endif


/*-----------------------------------------------------------------------------*/
/* Debug Variables & Functions Prototype                                       */
/*-----------------------------------------------------------------------------*/
#if ( HDMA_REG_MENU )
// functions
static ercode _dbgFun_HDMA_OPEN( u32 *pu32Par );
//static ercode _dbgFun_HDMA_MMAP_TESTING( u32 *pu32Par );
static ercode _dbgFun_HDMA_SrcIncreDstFixed( u32 *pu32Par );
static ercode _dbgFun_HDMA_SrcIncreDstIncre( u32 *pu32Par );
//static ercode _dbgFun_HDMA_SrcFixedDstFixed( u32 *pu32Par );
static ercode _dbgFun_HDMA_SrcFixedDstIncre( u32 *pu32Par );
static ercode _dbgFun_HDMA_DstAddrInDRAM( u32 *pu32Par );

static ercode _dbgFun_HDMA_SrcIncreDstFixed2( u32 *pu32Par );
static ercode _dbgFun_HDMA_SrcIncreDstIncre2( u32 *pu32Par );
//static ercode _dbgFun_HDMA_SrcFixedDstFixed2( u32 *pu32Par );
static ercode _dbgFun_HDMA_SrcFixedDstIncre2( u32 *pu32Par );
static ercode _dbgFun_HDMA_DstAddrInDRAM2( u32 *pu32Par );
static ercode _dbgFun_HDMA_DstAddrInDRAM3(u32 * pu32Par);

static ercode _dbgFun_HDMA_TestAll( u32 *pu32Par );
static ercode _dbgFun_HDMA_ShowRevision( u32 *pu32Par );

// commands
static ST_DRV_DBG_CMD _dbgCmd_HDMA_Open             = { _dbgFun_HDMA_OPEN, { 0, 0, 0, 0 } };
//static ST_DRV_DBG_CMD _dbgCmd_HDMA_MmapTesting      = { _dbgFun_HDMA_MMAP_TESTING, { 0, 0, 0, 0 } };
static ST_DRV_DBG_CMD _dbgCmd_HDMA_SrcIncreDstFixed = { _dbgFun_HDMA_SrcIncreDstFixed, { STR_DBG_TRIGGER_MODE_CHOOSE, STR_DGB_TEST_COUNT, 0, 0 } };
static ST_DRV_DBG_CMD _dbgCmd_HDMA_SrcIncreDstIncre = { _dbgFun_HDMA_SrcIncreDstIncre, { STR_DBG_TRIGGER_MODE_CHOOSE, STR_DGB_TEST_COUNT, 0, 0 } };
//static ST_DRV_DBG_CMD _dbgCmd_HDMA_SrcFixedDstFixed = { _dbgFun_HDMA_SrcFixedDstFixed, { STR_DBG_TRIGGER_MODE_CHOOSE, STR_DGB_TEST_COUNT, 0, 0 } };
static ST_DRV_DBG_CMD _dbgCmd_HDMA_SrcFixedDstIncre = { _dbgFun_HDMA_SrcFixedDstIncre, { STR_DBG_TRIGGER_MODE_CHOOSE, STR_DGB_TEST_COUNT, 0, 0 } };
static ST_DRV_DBG_CMD _dbgCmd_HDMA_DstAddrInDRAM    = { _dbgFun_HDMA_DstAddrInDRAM,    { STR_DBG_TRIGGER_MODE_CHOOSE, STR_DGB_TEST_COUNT, STR_DGB_TEST_ADDR_DATA_PATTERN, 0 } };
static ST_DRV_DBG_CMD _dbgCmd_HDMA_TestAll          = { _dbgFun_HDMA_TestAll,          { STR_DBG_TRIGGER_MODE_CHOOSE, STR_DGB_TEST_COUNT, 0, 0 } };
static ST_DRV_DBG_CMD _dbgCmd_HDMA_ShowRevision     = { _dbgFun_HDMA_ShowRevision, { 0, 0, 0, 0 } };

// menus
static ST_DRV_DBG_MENU _dbgMenu[] = {
    { DRV_DBG_TYPE_COMMAND, "Open HDMA",                 &_dbgCmd_HDMA_Open },
    //{ DRV_DBG_TYPE_COMMAND, "Test MMAP",                 &_dbgCmd_HDMA_MmapTesting },
    { DRV_DBG_TYPE_COMMAND, "Test Src incre, Dst fixed", &_dbgCmd_HDMA_SrcIncreDstFixed },
    { DRV_DBG_TYPE_COMMAND, "Test Src incre, Dst incre", &_dbgCmd_HDMA_SrcIncreDstIncre },
    //{ DRV_DBG_TYPE_COMMAND, "Test Src fixed, Dst fixed", &_dbgCmd_HDMA_SrcFixedDstFixed },
    { DRV_DBG_TYPE_COMMAND, "Test Src fixed, Dst incre", &_dbgCmd_HDMA_SrcFixedDstIncre },
    { DRV_DBG_TYPE_COMMAND, "Test Dst addr in DRAM",     &_dbgCmd_HDMA_DstAddrInDRAM },
    { DRV_DBG_TYPE_COMMAND, "Test All",                  &_dbgCmd_HDMA_TestAll },
    { DRV_DBG_TYPE_COMMAND, "Show Revision",             &_dbgCmd_HDMA_ShowRevision },
    { DRV_DBG_TYPE_TOTAL, NULL, NULL }
};
#endif // #if ( _REG_DBG_MENU_DBG == _ON )

/*-----------------------------------------------------------------------------*/
/* Interface Functions                                                         */
/*-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------*/
/* Module Functions                                                            */
/*-----------------------------------------------------------------------------*/

#ifdef KER_SUPPORT_LEON_FILL_GAMA

u32 u32LeonSramVirAddr;


/*************************************************************************
            Leon Address map for index
    index 0  : 0x20000000 ~ 0x27ffffff
    index 1  : 0x28000000 ~ 0x2fffffff
    index 2  : 0x30000000 ~ 0x37ffffff
    index 3  : 0x38000000 ~ 0x3fffffff
    index 4  : 0x40000000 ~ 0x47ffffff
    index 5  : 0x48000000 ~ 0x4fffffff
    index 6  : 0x50000000 ~ 0x57ffffff
    index 7  : 0x58000000 ~ 0x5fffffff
    index 8  : 0x60000000 ~ 0x67ffffff
    index 9  : 0x68000000 ~ 0x6fffffff
    index 10 : 0x70000000 ~ 0x77ffffff
    index 11 : 0x78000000 ~ 0x7fffffff
    index 12 : 0x80000000 ~ 0x87ffffff
    index 13 : 0x88000000 ~ 0x8fffffff
    index 14 : 0x90000000 ~ 0x97ffffff
    index 15 : 0x98000000 ~ 0x9fffffff
        
**************************************************************************/

#define WRITE_LEON_ADDRAMP(id,value)	(*(unsigned long volatile *)(MA_KER_REG_REMAP(0xFC1C0190) + (id << 2 ))=(value))

//leon SRAM start address 0xEFFE0000

void KER_LEON_INIT(void)
{
	u32 LeonBasicAddr = MA_KER_REG_REMAP(0xFC1C0000);
	//u32 u32SramVirAddr = (u32)ioremap(0xEFFE0000, 0x4000);// 16K
	u8 *pBuf = (u8 *)u32LeonSramVirAddr;
	u32 u32PC = 0;
	u32 u32PrevPC = 0;
	int icount = 200;
	volatile u32 u32IsLeonStart = 0;
	u32 k = 0;

	*((u32 *)(MA_KER_REG_REMAP(0xFd620000))) = 0;
	

	memcpy(pBuf,leon2text,sizeof(leon2text)); // text at 0xEFFE0000
	pBuf = (u8 *)(u32LeonSramVirAddr + 0x2000);
	memcpy(pBuf,leon2data,sizeof(leon2data)); // data at 0xEFFE2000
	pBuf = (u8 *)(u32LeonSramVirAddr + 0x4000);
	memset(pBuf, 0, 0x400); // information at 0xEFFE4000 ~ 0xEFFE4400

	//Register(0xfd02006c) = (1 << 10) | (1 << 11); //leon2 reset apb/core enable
    KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE, 1);
   // KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE2, 1);

    //Register(0xfd020068) |= (1 << 11); //leon2 reset apb disable
    KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE2, 0);

	// Fill leon instruction code
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x180) ) = 0x033bff60;
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x184) ) = 0x81c04000;
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x188) ) = 0x01000000;
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x18c) ) = 0x01000000;


	//WRITE_LEON_ADDRAMP(4, 0x0); //Real DRAM 0 ~ 128MB map to Leon
    //WRITE_LEON_ADDRAMP(5, 0x1); //Real DRAM 128 ~ 256MB map to Leon
    WRITE_LEON_ADDRAMP(6, 0x1d); //192KB SRAM 0 ~ 192KB map to Leon

	//mailbox init
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x160) ) = 0;
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x164) ) = 0;
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x168) ) = 0;
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x16c) ) = 0;

	//(*((volatile unsigned long *)   MA_KER_REG_REMAP(0xfd650000))) = 0x00007bbf; //Leon secure enable
	//acp enable
	//(*((volatile unsigned long *)   MA_KER_REG_REMAP(0xfd6b043c))) = 0x009fffcc; 
    //(*((volatile unsigned long *)   MA_KER_REG_REMAP(0xfd150084))) = 0xff000000;
    //(*((volatile unsigned long *)   MA_KER_REG_REMAP(0xfd140084))) = 0xff000000;
    //(*((volatile unsigned long *)   MA_KER_REG_REMAP(0xfd120084))) = 0xff000000;

	*((volatile unsigned long *)   (LeonBasicAddr  + 0x108) ) = 0x3; // disable leon INT
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x104) ) = 0x3; // clear Leon INT

	//leon core reset release in clkgen
    //(*((volatile unsigned long *)   MA_KER_REG_REMAP(0xfd020068))) |= (1 << 10);

	//Register(0xfd020068) |= (1 << 10); //leon2 reset core disable
    KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE, 0);

	*((volatile unsigned long *)   (LeonBasicAddr  + 0x114) ) = 0x5a;
    *((volatile unsigned long *)   (LeonBasicAddr  + 0x118) ) = 0x5a;

	
	icount = 500;
	do
	{
		u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
		//if(u32PC > 0x57fd8260 && u32PC < 0xeffd8000)
		if(u32PC >= 0x57fd8268 && u32PC <= 0x57fd8294)
		{
			break;
		}
		icount--;
	}while(icount > 0);

	
	KER_HDMA_MSG("Leon init\n");
	//reset Leon again

	{
		*((volatile unsigned long *)   (LeonBasicAddr  + 0x108) ) = 0x3; // disable leon INT
		*((volatile unsigned long *)   (LeonBasicAddr  + 0x104) ) = 0x3; // clear Leon INT
		u32PrevPC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
		KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE, 1);
		u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
		u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
		u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
		u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
		KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE, 0);
		//vk_printk("#############Leon2 reset111111(0x%x),prev(0x%x),cnt:%d \n",u32PC,u32PrevPC,icount);
	}


	icount = 200;
	for(k = 0 ; k < 10; k++)
	{
		u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
		u32PrevPC = u32PC;
		while(icount > 0)
		{
			u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
			if(u32PC > 0)
			{
				if(u32PrevPC != u32PC)
				{
					u32IsLeonStart = 1;
					//vk_printk("############LeonPC(0x%08x),k:%d,prev(0x%08x),Cnt:%d\n",u32PC,k,u32PrevPC,icount);
					break;
				}
				u32PrevPC = u32PC;
			}
			icount--;
		}

		if(u32IsLeonStart == 0)
		{
			*((volatile unsigned long *)   (LeonBasicAddr  + 0x108) ) = 0x3; // disable leon INT
			*((volatile unsigned long *)   (LeonBasicAddr  + 0x104) ) = 0x3; // clear Leon INT
			KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE, 1);
			u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
			u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
			u32PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
			KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE, 0);
			//vk_printk("#############Leon2 reset k:%d \n",k);
		}
		
		if(u32IsLeonStart == 1)
		{
			break;
		}
		icount = 200;
	}

	if(u32IsLeonStart != 1)
	{
		KER_HDMA_ERR("*************Leon 2 core clock enable fail \n");
	}


#if 0
{
	u32 iii;
	u32 PcTemp[100] = {0};
	for(iii = 0 ; iii < 100; iii ++)
	{
		PcTemp[iii] = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );
	}

	for(iii = 0 ; iii < 100; iii ++)
	{
	 vk_printk("############LeonPC(0x%08x)\n",(u32)PcTemp[iii]);
	}
}
#endif

	//PC = *((volatile unsigned long *)   (LeonBasicAddr  + 0x144) );

}


void KER_LEON_Disable(void)
{
	u32 LeonBasicAddr = MA_KER_REG_REMAP(0xFC1C0000);
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x114) ) = 0;
    *((volatile unsigned long *)   (LeonBasicAddr  + 0x118) ) = 0;

	*((volatile unsigned long *)   (LeonBasicAddr  + 0x108) ) = 0x3; // disable leon INT
	*((volatile unsigned long *)   (LeonBasicAddr  + 0x104) ) = 0x3; // clear Leon INT

	//Register(0xfd02006c) = (1 << 10) | (1 << 11); //leon2 reset apb/core enable
    KER_CLK_SetClockReset(EN_KER_CLK_RST_CORE_LEONCPU_CORE, 1);
}

#endif

static char *nvt_hdma_devnode(struct device *dev, umode_t *mode)
{
	if(mode)
	{
		*mode = 0666;
	}
	return NULL;
}

int KER_HDMA_DrvInit( void )
{
	s32   s32RetVal = 0;
	dev_t dev;
	
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	u32 irq;
	struct device_node* np = NULL;
	int irq_affinity=0;
#endif

    //	HDMA_MSG( HDMA_INF "driver loading...\r\n" );

    if( g_b8HDMAInit == TRUE ) {
        KER_HDMA_MSG( HDMA_INF "driver loaded > can't load twice\r\n" );
        return 0;
    }
	
#if (HDMA_SUPPORT_SUSPEND_MODE == ENABLE)
	_ker_hdma_pm_init_p();
#endif

	if(0 == hdma_major)
	{
		s32RetVal = alloc_chrdev_region(&dev, 0, 1, KER_HDMA_NAME);
    		hdma_major = MAJOR(dev);
	}
	else
	{
		dev = VK_MKDEV(hdma_major, 0);
		s32RetVal = vk_register_chrdev_region(dev, 1, KER_HDMA_NAME);
	}
	
	if(s32RetVal != 0)
	{
		KER_HDMA_ERR( HDMA_ERR "can't reg c_dev %d,%d\n", KER_HDMA_MAJOR, 0 );
		goto ERROR_PROC;
	}
	
	memset(&hdmadevice, 0, sizeof(hdmadevice));
	vk_cdev_init( &hdmadevice.cdev, &gstHDMAOps );
	hdmadevice.cdev.owner = VK_THIS_MODULE;
	s32RetVal = vk_cdev_add( &hdmadevice.cdev, dev, 1 );
	if(0 == s32RetVal) {
		hdmadevice.hdma_class = class_create(THIS_MODULE, KER_HDMA_NAME);
		hdmadevice.hdma_class->devnode = nvt_hdma_devnode;
		if (IS_ERR(hdmadevice.hdma_class)) {
			s32RetVal = PTR_ERR(hdmadevice.hdma_class);
			vk_cdev_del(&hdmadevice.cdev);
		} 
		else 
		{
			struct device *mdev;
			mdev = device_create(hdmadevice.hdma_class, NULL, dev, NULL, KER_HDMA_NAME);
			if (IS_ERR(mdev)) {
				s32RetVal = PTR_ERR(mdev);
				class_destroy(hdmadevice.hdma_class);
				vk_cdev_del(&hdmadevice.cdev);
			}
		}
	}
	if(s32RetVal) {
		vk_unregister_chrdev_region( dev, 1 );
		KER_HDMA_ERR( HDMA_ERR "can't add c_dev %d,%d\n", hdma_major, 0 );
		goto ERROR_PROC;
	}

	gpstDriver = &gstHDMADriver;
	gpstDriver->pfOpen();
	
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	np = of_find_node_by_name(NULL, KER_HDMA_NAME);
	if (np == NULL)
	{
		KER_HDMA_ERR( HDMA_ERR ">>>error node not found\n");
		s32RetVal = -1;
		goto ERROR_PROC;
	}
	else
	{
	    irq = irq_of_parse_and_map(np, 0);
	    s32RetVal = vk_request_irq(irq, _hdmaInterruptHandler, 0 | IRQF_TRIGGER_HIGH, KER_HDMA_NAME, NULL);
	    of_property_read_u32(np, "interrupt-affinity", &irq_affinity);
	    if (irq_affinity < num_online_cpus() && irq_affinity > 0)
            	irq_set_affinity_hint( irq, cpumask_of(irq_affinity) );
	}
#else  
	s32RetVal = vk_request_irq( EN_KER_IRQ_ID_AHBDMA, _hdmaInterruptHandler, 0 | IRQF_TRIGGER_HIGH, KER_HDMA_NAME, NULL );
#endif

	if( s32RetVal < 0 ) {
		device_destroy(hdmadevice.hdma_class, dev);
		class_destroy(hdmadevice.hdma_class);
		vk_cdev_del( &hdmadevice.cdev );
		vk_unregister_chrdev_region( dev, 1 );
		KER_HDMA_ERR( HDMA_ERR "can't request IRQ for %d,%d\n", KER_HDMA_MAJOR, 0 );
		goto ERROR_PROC;
	}
#if (ENABLE == HDMA_SUPPORT_SUSPEND_MODE)
		vk_mutex_init(&gstHDMA_HW_Exexuting_Mutex);
#endif

#if( KER_HDMA_TEST )
    //<! Allocate contiguous memory to mmap to user space. >
    #if 0
    order = get_order( gu32HDMAMemSize );
    page = alloc_pages( GFP_KERNEL | GFP_DMA, order );

    
	if( page == NULL ) {
        KER_HDMA_ERR( "Can not allocate contiguous memory %d bytes!\n", gu32HDMAMemSize );
    } 
	else
    {
    	gpu32HDMAMemVirtAddr = page_address( page );
		//memset(gpu32HDMAMemVirtAddr,0,gu32HDMAMemSize);
        gu32HDMAMemPhysAddr = virt_to_phys( gpu32HDMAMemVirtAddr );
        KER_HDMA_MSG( "HDMA mem phys addr 0x%08X, virt addr 0x%08X!\n", gu32HDMAMemPhysAddr, ( u32 )gpu32HDMAMemVirtAddr );
    }
   #else
   gpu32HDMAMemVirtAddr = (u32 *) dma_alloc_coherent (NULL, gu32HDMAMemSize, &dma_handle,  GFP_KERNEL | GFP_DMA);
   if (gpu32HDMAMemVirtAddr != 0) 
   {
	   gu32HDMAMemPhysAddr = (u32)dma_handle;
   	   KER_HDMA_MSG( "HDMA mem phys addr 0x%08X, virt addr 0x%08X! \n", gu32HDMAMemPhysAddr, ( u32 )gpu32HDMAMemVirtAddr );
   }
   else
   {
	   KER_HDMA_MSG( "HDMA allocate buffer fail\n");
   }
   #endif
#endif

#ifdef KER_SUPPORT_LEON_FILL_GAMA
	u32LeonSramVirAddr = (u32)ioremap(0xEFFD8000, 0x4400);// 17K, 0xEFFD8000 ~ 0xEFFDC400
	KER_LEON_INIT();
#endif

#if ( HDMA_REG_MENU == ENABLE )
    DRV_DBG_Register( EN_DRV_DBG_LAYER_DRV, EN_DRV_DBG_TYPE_SUBMENU, "DRV_HDMA", _dbgMenu );
    KER_DBG_Enable(EN_KER_DBG_HDMA);
#endif
ERROR_PROC:

    if( s32RetVal ) {
        g_b8HDMAInit = FALSE;
        KER_HDMA_ERR( HDMA_ERR "driver loaded > ERROR !!!\r\n" );
    } else {
        g_b8HDMAInit = TRUE;
		KER_HDMA_MSG( HDMA_INF "driver loaded > OK\r\n" );
    }

    return s32RetVal;
}

void KER_HDMA_DrvExit( void )
{
    dev_t dev;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
    struct device_node* np;
	int irq_num;
#endif
    KER_HDMA_MSG( HDMA_INF "driver unloading...\r\n" );

    if( g_b8HDMAInit == TRUE ) {
        dev = VK_MKDEV( hdma_major, 0 );
		device_destroy(hdmadevice.hdma_class, dev);
	    class_destroy(hdmadevice.hdma_class);
		
        gpstDriver->pfClose();
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
		np = of_find_node_by_name(NULL, "WOW");
		if (np != NULL)
		{
		    irq_num = irq_of_parse_and_map(np,0);
		    vk_disable_irq( irq_num );

		    irq_set_affinity_hint(irq_num, NULL);

		    vk_free_irq( irq_num, NULL );
		}
#else
        vk_disable_irq( EN_KER_IRQ_ID_AHBDMA );
        vk_free_irq( EN_KER_IRQ_ID_AHBDMA, NULL );
#endif
        vk_cdev_del( &hdmadevice.cdev );
        vk_unregister_chrdev_region( dev, 1 );
        g_b8HDMAInit = FALSE;
        dma_free_coherent(NULL, gu32HDMAMemSize, gpu32HDMAMemVirtAddr,gu32HDMAMemPhysAddr); 
		KER_HDMA_MSG( HDMA_INF "driver unloaded > OK\r\n" );
    } else {
        KER_HDMA_ERR( HDMA_INF "driver unloaded > ERROR !!!\r\n" );
    }

    return;
}

/*-----------------------------------------------------------------------------*/
/* Task Functions                                                              */
/*-----------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------*/
/* Local Functions                                                             */
/*-----------------------------------------------------------------------------*/
static long _hdmaIoctl( struct vos_file *pstFile, unsigned int u32Cmd, unsigned long u32Arg )
{
    int iError = ENOERR;
	
#if (ENABLE == HDMA_SUPPORT_SUSPEND_MODE)
	vk_mutex_lock(&gstHDMA_HW_Exexuting_Mutex);
#endif

    switch( u32Cmd ) {
        case KER_HDMA_IO_COPY_PHYS_TO_PHYS:
        case KER_HDMA_IO_FILL_PHYS: {
            if( u32Arg != KER_HDMA_IO_INVALID_PARAM ) {
                KER_HDMA_MSG( "\n\n\n ***********************************************************************************************\n" );
                KER_HDMA_MSG( "Using ioctl directly is not allowed. Check if drivers use HDMA ioctl and set parameter directly\n" );
                KER_HDMA_MSG( "***********************************************************************************************\n\n\n" );
            }
			iError = _hdmaFillPhys();
            break; 
        }

        case KER_HDMA_IO_GET_BUFF_ADDR: {
            if( vk_copy_to_user( ( void __user * )u32Arg, &gu32HDMAMemPhysAddr, sizeof( u32 ) ) ) {
                iError = -EFAULT;
	            break; 
            }

            break;
        }

        case KER_HDMA_IO_GET_BUFF_DATA: {
            u32 u32Index;
            u32 u32RetData;

            if( vk_copy_from_user( (void*)&u32Index, ( void __user * )u32Arg, sizeof( u32 ) ) ) {
                iError = -EFAULT;
	            break; 
            }
		if(gu32HDMAMemSize <=  (u32Index * 4) )
		{
			KER_HDMA_ERR( "Require address is out of memory \n" );
			iError = -EFAULT;
			break;
		}
            if ( u32Index < (gu32HDMAMemSize >> 2) && (gpu32HDMAMemVirtAddr + u32Index) != 0)
            	{
				u32RetData = *((volatile u32 *)gpu32HDMAMemVirtAddr + u32Index);

            if( vk_copy_to_user( ( void __user * )u32Arg, &u32RetData, sizeof( u32 ) ) ) {
                iError =  -EFAULT;
				//break;
            }
            	}
			else
				{
					iError = -EFAULT;
				}
            break;

        }

        default: {
            KER_HDMA_ERR( "\n\n\n ***********************************************************************************************\n" );
            KER_HDMA_ERR( "HDMA ioctl command error (%d)! Only allow COPY_PHYS_TO_PHYS & FILL_PHYS\n", u32Cmd );
            KER_HDMA_ERR( "Check user driver if you use invalid ioctl command.\n" );
            KER_HDMA_ERR( "***********************************************************************************************\n\n\n" );
            iError =   -EINVAL;
			break;
        }
    }
#if (ENABLE == HDMA_SUPPORT_SUSPEND_MODE)	
	vk_mutex_unlock(&gstHDMA_HW_Exexuting_Mutex);
#endif
    return iError;
}


#if( KER_HDMA_TEST )
static int _hdmaMmap( struct vos_file *pstFile, struct vm_area_struct *pstVMA )
{
#if 0
    dma_addr_t dmaAddr;
    void *virtAddr;
    u32 off;
    virtAddr = dma_alloc_writecombine( NULL, pstVma->vm_end - pstVma->vm_start, &dmaAddr, GFP_KERNEL );

    if( virtAddr == NULL ) {
        return -ENOMEM;
    }

    off = pstVma->vm_pgoff << PAGE_SHIFT;
    off += dmaAddr;
    pstVma->vm_pgoff = off >> PAGE_SHIFT;
    pstVma->vm_flags |= VM_IO | VM_RESERVED;
    pstVma->vm_page_prot = pgprot_noncached( pstVma->vm_page_prot );

    if( io_remap_pfn_range( pstVma, pstVma->vm_start, off >> PAGE_SHIFT,
                            pstVma->vm_end - pstVma->vm_start, pstVma->vm_page_prot ) ) {
        return -EAGAIN;
    }

    return 0;
#else
    u32 off = pstVMA->vm_pgoff << PAGE_SHIFT;
    u32 physAddr = gu32HDMAMemPhysAddr + off;
    u32 virtSize = pstVMA->vm_end - pstVMA->vm_start;
    u32 physSize = gu32HDMAMemSize - off;

    if( gu32HDMAMemPhysAddr == 0 ) {
        return -EINVAL;
    }

    if( virtSize > physSize ) {
        return -EINVAL;
    }

    pstVMA->vm_flags |= VM_IO | VM_DONTDUMP;
	 #if defined(KER_OS_ECOS)
	   pstVMA->vm_page_prot = vk_pgprot_noncached( pstVMA->vm_page_prot ); // Jeff add

          if( vk_io_remap_pfn_range( pstVMA, pstVMA->vm_start, physAddr >> PAGE_SHIFT, virtSize, pstVMA->vm_page_prot ) < 0 ) {
		
    
	 #else
	  pstVMA->vm_page_prot = pgprot_noncached( pstVMA->vm_page_prot ); // Jeff add

         if( io_remap_pfn_range( pstVMA, pstVMA->vm_start, physAddr >> PAGE_SHIFT, virtSize, pstVMA->vm_page_prot ) < 0 ) {
       
	 #endif
   
    return -EAGAIN;
		}

#endif

    return 0;
}
#endif

static int _hdmaFillPhys( void )
{
    int ret = 0;
    ret = gpstDriver->pfStartDataTransfer();
    return ret;
}



#if (LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 21))
static irqreturn_t _hdmaInterruptHandler( int irq, void *dev_id )
#else
static irqreturn_t _hdmaInterruptHandler( int irq, void *dev_id, struct pt_regs *regs )
#endif
{
    gpstDriver->pfTransferComplete();

    return IRQ_HANDLED;
}

#if (HDMA_SUPPORT_SUSPEND_MODE == ENABLE)
static void _ker_hdma_pm_init_p (void)
{
	KER_PMI_ActScript_t stAct;
	memset( &stAct, 0 , sizeof( KER_PMI_ActScript_t ) );
	
#if (KER_PMI_CENTER == 0)
	char name[] = KER_HDMA_NAME; 
	bus_register(&_ker_hdma_bus);    

	_ker_hdma_dev.init_name = name;
	device_register(&_ker_hdma_dev);

	stAct.resume = _ker_hdma_pmi_p;
	stAct.suspend = _ker_hdma_pmi_p;
	stAct.prepare = NULL;
#else
	stAct.resume = _ker_hdma_resume_p;
	stAct.suspend = _ker_hdma_suspend_p;
	stAct.prepare = NULL;
	//for SS IOT
	stAct.poweroff = _ker_hdma_suspend_p;
	stAct.poweroff_late = NULL;
	stAct.power_resume = _ker_hdma_resume_p;
	stAct.power_resume_early = NULL;
	stAct.power_suspend = NULL;
	stAct.power_restore = NULL;
#endif	
	memset((void*)&st_HDMA_Suspend_HW_PAR, 0, sizeof(ST_KER_HDMA_PARAMS)); 
	KER_PMI_Install (	KER_PMI_CLASS_HDMA,
						KER_PMI_CLASS_SYSTEM,
						&stAct,
						10,
						0,
						(void*)&_ker_hdma_dev);
}

static int _ker_hdma_suspend_p (struct device *dev)
{    
	unsigned long start_time;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	u32 irq;
	struct device_node* np = NULL;
#endif
    KER_HDMA_MSG("<<<< KHDMA: suspend >>>>\n");

	start_time = jiffies;
 vk_printk(KERN_INFO "@suspend(in) %s\n", __func__);

#if (KER_PMI_CENTER)
	vk_mutex_lock(&gstHDMA_HW_Exexuting_Mutex);
	//collect the source, dst, size, mode information 
	if(gpstDriver->pfGetHWStatus(&st_HDMA_Suspend_HW_PAR))
	{
		KER_HDMA_ERR( "Get H/W status error \n" );
		vk_mutex_unlock(&gstHDMA_HW_Exexuting_Mutex);
		return -EINVAL;
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	np = of_find_node_by_name(NULL, KER_HDMA_NAME);
	if (np == NULL)
	{
		KER_HDMA_ERR( HDMA_ERR ">>>error node not found\n");
		return -1;
	}
	else
	{
	    irq = irq_of_parse_and_map(np, 0);
	    vk_disable_irq(irq);//disable the interrupt 
	}
#else  
	vk_disable_irq(EN_KER_IRQ_ID_AHBDMA);//disable the interrupt 
#endif

#ifdef KER_SUPPORT_LEON_FILL_GAMA
	KER_LEON_Disable();
#endif

	if(KER_PMI_Mode() == KER_PMI_MODE_IOT)
	{
		KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_HDMA, FALSE);
		KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_HDMA, FALSE);
		
		KER_HDMA_MSG("PMI Suspend for iot mode done.\n");
	}	
	
#else
	genXdmaPMICmdStatus = KER_PMI_CMD_SUSPEND;	
	KER_PMI_Notify (KER_PMI_CLASS_HDMA, genHdmaPMICmdStatus);
#endif
	
 vk_printk(KERN_INFO "@suspend_time/%s/%d/msec\n", __func__, jiffies_to_msecs(jiffies - start_time));
	
	return 0;
}

static int _ker_hdma_resume_p (struct device *dev)
{
	unsigned long start_time;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	u32 irq;
	struct device_node* np = NULL;
#endif
    KER_HDMA_MSG("<<<< KHDMA: resume >>>>\n");

	start_time = jiffies;
 vk_printk(KERN_INFO "@resume(in) %s\n", __func__);

#if (KER_PMI_CENTER)
	if(gpstDriver->pfSetHWStatus(&st_HDMA_Suspend_HW_PAR))
	{
		KER_HDMA_ERR( "Set H/W status error \n" );
		return -EINVAL;
	}		
	//KER_PMI_Notify (KER_PMI_CLASS_XDMA, KER_PMI_CMD_RESUME);  
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
		np = of_find_node_by_name(NULL, KER_HDMA_NAME);
		if (np == NULL)
		{
			KER_HDMA_ERR( HDMA_ERR ">>>error node not found\n");
			return -1;
		}
		else
		{
		    irq = irq_of_parse_and_map(np, 0);
		    vk_enable_irq(irq);
		}
#else  
		vk_enable_irq(EN_KER_IRQ_ID_AHBDMA);//Enable the interrupt 
#endif


#ifdef KER_SUPPORT_LEON_FILL_GAMA
	KER_LEON_INIT();
#endif

	if(KER_PMI_Mode() == KER_PMI_MODE_IOT)
	{
		KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_HDMA, TRUE);
		KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_HDMA, TRUE);

		KER_HDMA_MSG("PMI Resume for iot mode done.\n");
	}

	vk_mutex_unlock(&gstHDMA_HW_Exexuting_Mutex);
	
 vk_printk(KERN_INFO "@resume_time/%s/%d/msec\n", __func__, jiffies_to_msecs(jiffies - start_time));
	
	return 0;
#else
	genHdmaPMICmdStatus = KER_PMI_CMD_RESUME;	
	KER_PMI_Notify (KER_PMI_CLASS_HDMA, genHdmaPMICmdStatus);
#endif
}
#if (KER_PMI_CENTER == 0)
static int _ker_hdma_pmi_p (struct device *pstDevice) 
{	switch (genHdmaPMICmdStatus) 	
	{		
		case KER_PMI_CMD_SUSPEND:		
		{			
			vk_mutex_lock(&gstHDMA_HW_Exexuting_Mutex);
			//collect the source, dst, size, mode information 
			if(gpstDriver->pfGetHWStatus(&st_HDMA_Suspend_HW_PAR))
			{
				KER_HDMA_ERR( "Get H/W status error \n" );
				vk_mutex_unlock(&gstHDMA_HW_Exexuting_Mutex);
				return -EINVAL;
			}
			vk_disable_irq(EN_KER_IRQ_ID_AHBDMA);//disable the interrupt 			
			break;		
		}		
		case KER_PMI_CMD_RESUME:		
		{			
			if(gpstDriver->pfSetHWStatus(&st_HDMA_Suspend_HW_PAR))
			{
				KER_HDMA_ERR( "Set H/W status error \n" );
				return -EINVAL;
			}		
			//KER_PMI_Notify (KER_PMI_CLASS_XDMA, KER_PMI_CMD_RESUME);  
			vk_enable_irq(EN_KER_IRQ_ID_AHBDMA);//disable the interrupt 
			vk_mutex_unlock(&gstHDMA_HW_Exexuting_Mutex);
			break;		
		}		
		case KER_PMI_CMD_INVALID:		
		default:		
		{			
			KER_HDMA_ERR("[%s]Parameter is invalid \n", __FUNCTION__);			
			break;		
		}	
	}		
	return 0;
}
#endif

#endif



int HdmaTrigger( void )
{
    int ret = 0;
    ret = gpstDriver->pfStartDataTransfer();
    return ret;
}



u32 HDMA_GetPhysicalAds( void )
{
	return gu32HDMAMemPhysAddr;
}

void * HDMA_GetVirtialAds( void )
{
	return gpu32HDMAMemVirtAddr;
}

#ifdef KER_SUPPORT_LEON_FILL_GAMA
#define SUPPORT_LEON_FILL_GAMA
#endif

#define ERR_NOERR                0      /* No Error */
#define ERR_INVAL                22     /* Invalid argument */

/*-----------------------------------------------------------------------------*/
/* Local Constant Definitions                                                  */
/*-----------------------------------------------------------------------------*/

#ifdef SUPPORT_LEON_FILL_GAMA
#define LEON_REG_BASE	(0xFC1C0000)
#endif


/*-----------------------------------------------------------------------------*/
/* Local Types Declarations                                                    */
/*-----------------------------------------------------------------------------*/
typedef struct _ST_DRV_HDMA_CONTEXT {
    s32 s32Fd;
} ST_DRV_HDMA_CONTEXT;


/*-----------------------------------------------------------------------------*/
/* Extern Global Variables                                                     */
/*-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------*/
/* Extern Function Prototype                                                   */
/*-----------------------------------------------------------------------------*/

/*-----------------------------------------------------------------------------*/
/* Local Function Prototype                                                    */
/*-----------------------------------------------------------------------------*/
static ercode _KER_HdmaStart( ST_DRV_HDMA_PARAMETER *pstParam );
static ercode _KER_HDMA_Complete( void );
#ifdef SUPPORT_LEON_FILL_GAMA
static ercode _KER_HdmaLeonStart( ST_DRV_HDMA_PARAMETER *pstParam );
#endif
static ST_DRV_HDMA_CONTEXT gstDRV_HDMAContext;
static ST_HDMA_XREG *g_pstHDMACtrlReg;
static ST_HDMA_HREG *g_pstAXI2AHBCtrlReg;
static void *gpu8_HDMAMmapBuffAddr = NULL;
static u32 gu32_HDMAKernelBuffAddr = 0;
static const u32 gu32_MmapMemSize  = ( 1024 << 5 ); // 32KB
static const u32 gu32HDMASplitSize = ( 1024 << 5 ); // 32KB
#ifdef SUPPORT_LEON_FILL_GAMA
typedef struct LEON_CTL_REG
{
	volatile u32 REG_LEON_CTL_INI_STS; 		//( LEON_REG_BASE + 0x100)
	volatile u32 REG_LEON_CTL_INI_CLR; 		//( LEON_REG_BASE + 0x104)
	volatile u32 REG_LEON_CTL_INI_MSK; 		//( LEON_REG_BASE + 0x108)
	volatile u32 REG_LEON_CTL_INI_2LEON; 	//( LEON_REG_BASE + 0x10c), Int to leon
	volatile u32 REG_LEON_CTL_SW_APB;		//( LEON_REG_BASE + 0x110)
	volatile u32 REG_LEON_CTL_WDOG_MSK;		//( LEON_REG_BASE + 0x114)
	volatile u32 REG_LEON_CTL_WDOG_EN;		//( LEON_REG_BASE + 0x118)
	volatile u32 REG_LEON_CTL_WDOG_STS;		//( LEON_REG_BASE + 0x11c)
}ST_LEON_CTL_REG;
typedef struct LEONG_MAILBOX_REG
{
	volatile u32 REG_LEON_IPC_MAILBOX0;  //RW ( LEON_REG_BASE + 0x160 ), command register [ 31: 0]
	volatile u32 REG_LEON_IPC_MAILBOX1;  //RW ( LEON_REG_BASE + 0x164 ), Information register [ 31: 0]
	volatile u32 REG_LEON_IPC_MAILBOX2;  //RW ( LEON_REG_BASE + 0x168 ), 
	volatile u32 REG_LEON_IPC_MAILBOX3;  //RW ( LEON_REG_BASE + 0x16c ), Table address [ 31 : 0]
	volatile u32 REG_LEON_IPC_MAILBOX4;  //R  ( LEON_REG_BASE + 0x170 ),
	volatile u32 REG_LEON_IPC_MAILBOX5;  //R  ( LEON_REG_BASE + 0x174 ), 
	volatile u32 REG_LEON_IPC_MAILBOX6;  //R  ( LEON_REG_BASE + 0x178 ), 
	volatile u32 REG_LEON_IPC_MAILBOX7;  //R  ( LEON_REG_BASE + 0x17c ),
}ST_LEONG_MAILBOX_REG;
ST_LEON_CTL_REG			*g_pstLeonCtlReg;
ST_LEONG_MAILBOX_REG 	*g_pstLeonMailboxReg;
#endif

/*-----------------------------------------------------------------------------*/
/* Debug Variables & Functions                                                 */
/*-----------------------------------------------------------------------------*/
static struct mutex gstHDMA_HWMutex;

/*-----------------------------------------------------------------------------*/
/* Interface Functions                                                         */
/*-----------------------------------------------------------------------------*/
ercode DRV_HDMA_Init( void )
{
    //DRV_HDMA_Open();
    return ERR_NOERR;
}
ercode DRV_HDMA_Open( void )
{
    ercode ret = ERR_NOERR;
    g_pstHDMACtrlReg = ( ST_HDMA_XREG * )MA_KER_REG_REMAP( HDMA_REG_BASE );
    g_pstAXI2AHBCtrlReg = ( ST_HDMA_HREG * )MA_KER_REG_REMAP( HDMA_REG_BASE + 0x80 );
//    g_pstHDMACtrlReg->unXDMABurstLen.val.u32Val = 0x00000000;
#ifdef SUPPORT_LEON_FILL_GAMA
	g_pstLeonCtlReg		= (ST_LEON_CTL_REG *) MA_KER_REG_REMAP( LEON_REG_BASE + 0x100); // Leon ctl start
	g_pstLeonMailboxReg = (ST_LEONG_MAILBOX_REG *) MA_KER_REG_REMAP( LEON_REG_BASE + 0x160); // Leon mailbox start
#endif
	gstDRV_HDMAContext.s32Fd = 1;
	vk_mutex_init(&gstHDMA_HWMutex);
	gu32_HDMAKernelBuffAddr = HDMA_GetPhysicalAds();
	gpu8_HDMAMmapBuffAddr = HDMA_GetVirtialAds();
    KER_HDMA_MSG( "Open HDMA success.\n" );

//EXIT_HDMA_INIT:
    return ret;
}
ercode DRV_HdmaTransfer( ST_DRV_HDMA_PARAMETER *pstParam )
{
    ercode ret = ERR_NOERR;
    u32 cnt = 0;
    if( gstDRV_HDMAContext.s32Fd <= 0 ) {
        KER_HDMA_ERR( "DRV_HDMA is not initialized!\n" );
        return ERR_INVAL;
    }
	vk_mutex_lock(&gstHDMA_HWMutex);
#ifdef SUPPORT_LEON_FILL_GAMA
	if(pstParam->u32FuncMode >= 2) 
	{
		ret = _KER_HdmaLeonStart( pstParam );
	}
	else
#endif
	{
	    do {
			ret = _KER_HdmaStart( pstParam );
	        if( ret != ERR_NOERR ) {
	            KER_HDMA_ERR("[HDMA] FAIL\n");
			    cnt++;
	            ret = ERR_INVAL;
			} else {
	            break;
	        }
	    } while( cnt < 3 );
	}
	vk_mutex_unlock(&gstHDMA_HWMutex);
    return ret;
}
EXPORT_SYMBOL( DRV_HdmaTransfer );

ercode DRV_HdmaTransfer_forQE( ST_DRV_HDMA_PARAMETER *pstParam )
{
	ercode ret = ERR_NOERR;
	vk_mutex_lock(&gstHDMA_HWMutex);

	if( gpu8_HDMAMmapBuffAddr == NULL )
	{
		KER_HDMA_ERR("[HDMA] gpu8_HDMAMmapBuffAddr ERROR\n");
		ret = ERR_INVAL;
	} 
	else
	{
		if( ( pstParam->enDMAMode != EN_DRV_HDMA_MODE_SRC_FIXED_DST_INCRE ) && ( pstParam->enDMAMode != EN_DRV_HDMA_MODE_SRC_FIXED_DST_FIXED ) )
		{
			memcpy( gpu8_HDMAMmapBuffAddr, ( void * )(uintptr_t)( pstParam->u32SrcVirAddr ), pstParam->u32DataSize );
			g_pstHDMACtrlReg->unXDMASrcAddr.val.u32Val = gu32_HDMAKernelBuffAddr;
		}
		g_pstHDMACtrlReg->unXDMADstAddr.val.u32Val = pstParam->u32DstPhyAddr;
		//g_pstHDMACtrlReg->unHDMAAxiIf.val.u32Val = 0x0;
		g_pstAXI2AHBCtrlReg->unHDMAHlineCounter.val.u32Val = pstParam->u32HLineCnt;
		g_pstAXI2AHBCtrlReg->unHDMAFuncMode.val.u32Val = pstParam->u32FuncMode;
		g_pstAXI2AHBCtrlReg->unHDMATriggerMode.val.u32Val |= ( 0x00000000 | pstParam->enTriggerMode );
		//HDMA_NEW
		g_pstHDMACtrlReg->unXDMAInterruptEn.val.u32Val = 0x1; // Enable finishing interrupt old:set 0 new:set 1

		switch( pstParam->enDMAMode )
		{
			case EN_DRV_HDMA_MODE_BOTH_INCRE:
				g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x0;
				break;
			case EN_DRV_HDMA_MODE_SRC_INCRE_DST_FIXED:
				g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x10;
				break;
			case EN_DRV_HDMA_MODE_SRC_FIXED_DST_INCRE:
				g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x1;
				break;
			case EN_DRV_HDMA_MODE_SRC_FIXED_DST_FIXED:
				g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x11;
				break;
			case EN_DRV_HDMA_MODE_DST_ADDR_IN_DRAM:
				g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x100;
				break;
			default:
				break;
		}

		if( pstParam->u32DataSize <= gu32HDMASplitSize )
		{
			g_pstHDMACtrlReg->unXDMAByteCnt.val.u32Val = pstParam->u32DataSize;
		
			g_pstHDMACtrlReg->unXDMAEnable.val.u32Val |= 0x1; // Trigger DMA
		}
		else
		{
			const u32 numSplitBlocks = pstParam->u32DataSize / gu32HDMASplitSize;
			const u32 numBytesLastBlock = pstParam->u32DataSize - gu32HDMASplitSize * numSplitBlocks;
			register u32 remainBlocks = numSplitBlocks;
			g_pstHDMACtrlReg->unXDMAByteCnt.val.u32Val = gu32HDMASplitSize;

			while( remainBlocks-- > 0 )
			{
				g_pstHDMACtrlReg->unXDMAEnable.val.u32Val |= 0x1; // Trigger DMA

				g_pstHDMACtrlReg->unXDMASrcAddr.val.u32Val += gu32HDMASplitSize;

				if( ( pstParam->enDMAMode == EN_DRV_HDMA_MODE_BOTH_INCRE ) || ( pstParam->enDMAMode == EN_DRV_HDMA_MODE_SRC_FIXED_DST_INCRE ) )
				{
					g_pstHDMACtrlReg->unXDMADstAddr.val.u32Val += gu32HDMASplitSize;
				}
			}
			// Last block
			if( numBytesLastBlock > 0 )
			{
				g_pstHDMACtrlReg->unXDMAByteCnt.val.u32Val = numBytesLastBlock;

				g_pstHDMACtrlReg->unXDMAEnable.val.u32Val |= 0x1; // Trigger DMA
			}
		}
	}
	
	vk_mutex_unlock(&gstHDMA_HWMutex);

	return ret;
}
EXPORT_SYMBOL( DRV_HdmaTransfer_forQE );

ercode DRV_HDMA_Close( void )
{
    ercode ret = ERR_NOERR;
    return ret;
}

static ercode _KER_HdmaStart( ST_DRV_HDMA_PARAMETER *pstParam )
{
    ercode ret = ERR_NOERR;
    if( gpu8_HDMAMmapBuffAddr == NULL ) {
		KER_HDMA_ERR("[HDMA] gpu8_HDMAMmapBuffAddr ERROR\n");
		ret = ERR_INVAL;
    } else {
    
        if( ( pstParam->enDMAMode != EN_DRV_HDMA_MODE_SRC_FIXED_DST_INCRE ) && ( pstParam->enDMAMode != EN_DRV_HDMA_MODE_SRC_FIXED_DST_FIXED ) ) {
            memcpy( gpu8_HDMAMmapBuffAddr, ( void * )(uintptr_t)( pstParam->u32SrcVirAddr ), pstParam->u32DataSize );
            g_pstHDMACtrlReg->unXDMASrcAddr.val.u32Val = gu32_HDMAKernelBuffAddr;
        }
        g_pstHDMACtrlReg->unXDMADstAddr.val.u32Val = pstParam->u32DstPhyAddr;
        //g_pstHDMACtrlReg->unHDMAAxiIf.val.u32Val = 0x0;
        g_pstAXI2AHBCtrlReg->unHDMAHlineCounter.val.u32Val = pstParam->u32HLineCnt;
        g_pstAXI2AHBCtrlReg->unHDMAFuncMode.val.u32Val = pstParam->u32FuncMode;
        g_pstAXI2AHBCtrlReg->unHDMATriggerMode.val.u32Val |= ( 0x00000000 | pstParam->enTriggerMode );
        //HDMA_NEW
		g_pstHDMACtrlReg->unXDMAInterruptEn.val.u32Val = 0x1; // Enable finishing interrupt old:set 0 new:set 1

		switch( pstParam->enDMAMode ) {
            case EN_DRV_HDMA_MODE_BOTH_INCRE:
                g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x0;
                break;
            case EN_DRV_HDMA_MODE_SRC_INCRE_DST_FIXED:
                g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x10;
                break;
            case EN_DRV_HDMA_MODE_SRC_FIXED_DST_INCRE:
                g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x1;
                break;
            case EN_DRV_HDMA_MODE_SRC_FIXED_DST_FIXED:
                g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x11;
                break;
            case EN_DRV_HDMA_MODE_DST_ADDR_IN_DRAM:
                g_pstAXI2AHBCtrlReg->unHDMABufferMode.val.u32Val = 0x100;
                break;
            default:
                break;
        }
        if( pstParam->u32DataSize <= gu32HDMASplitSize ) {
            g_pstHDMACtrlReg->unXDMAByteCnt.val.u32Val = pstParam->u32DataSize;
#if (HDMA_SUPPORT_SUSPEND_MODE != ENABLE)			
            g_pstHDMACtrlReg->unXDMAEnable.val.u32Val |= 0x1; // Trigger DMA
#endif

            if( _KER_HDMA_Complete() != ERR_NOERR ) {
				KER_HDMA_ERR("[HDMA] _KER_HDMA_Complete ERROR\n");
                ret = ERR_INVAL;
            }

        } else {
            const u32 numSplitBlocks = pstParam->u32DataSize / gu32HDMASplitSize;
            const u32 numBytesLastBlock = pstParam->u32DataSize - gu32HDMASplitSize * numSplitBlocks;
            register u32 remainBlocks = numSplitBlocks;
            g_pstHDMACtrlReg->unXDMAByteCnt.val.u32Val = gu32HDMASplitSize;
            while( remainBlocks-- > 0 ) {

#if (HDMA_SUPPORT_SUSPEND_MODE != ENABLE)
                g_pstHDMACtrlReg->unXDMAEnable.val.u32Val |= 0x00000001;
#endif

                if( _KER_HDMA_Complete() != ERR_NOERR ) {
                    ret = ERR_INVAL;
                }

                g_pstHDMACtrlReg->unXDMASrcAddr.val.u32Val += gu32HDMASplitSize;

                if( ( pstParam->enDMAMode == EN_DRV_HDMA_MODE_BOTH_INCRE ) || ( pstParam->enDMAMode == EN_DRV_HDMA_MODE_SRC_FIXED_DST_INCRE ) ) {
                    g_pstHDMACtrlReg->unXDMADstAddr.val.u32Val += gu32HDMASplitSize;
                }
            }

            // Last block
            if( numBytesLastBlock > 0 ) {
                g_pstHDMACtrlReg->unXDMAByteCnt.val.u32Val = numBytesLastBlock;
#if (HDMA_SUPPORT_SUSPEND_MODE != ENABLE)
                g_pstHDMACtrlReg->unXDMAEnable.val.u32Val |= 0x00000001;
#endif
                if( _KER_HDMA_Complete() != ERR_NOERR ) {
                    ret = ERR_INVAL;
                }
            }
        }
    }

    return ret;
}




int HdmaTrigger( void );

static ercode _KER_HDMA_Complete( void )
{
    ercode ret = ERR_NOERR;

	ret = HdmaTrigger();

    return ret;
}




#ifdef SUPPORT_LEON_FILL_GAMA
static ercode _KER_HdmaLeonStart( ST_DRV_HDMA_PARAMETER *pstParam )
{
	if(g_pstLeonMailboxReg == NULL || g_pstLeonCtlReg == NULL)
	{
		KER_HDMA_ERR("Error Leon register don't init \n");
		return ERR_INVAL;
	}

	if(pstParam == NULL)
	{
		KER_HDMA_ERR("Error pstParam is NULL \n");
		return ERR_INVAL; 
	}
	
	if( gpu8_HDMAMmapBuffAddr == NULL || gu32_HDMAKernelBuffAddr == 0) 
	{
		KER_HDMA_ERR("gpu8_HDMAMmapBuffAddr or gu32_HDMAKernelBuffAddr is NULL \n");
        return ERR_INVAL;
    }
	else
	{
		if(pstParam->u32SrcVirAddr == 0 || pstParam->u32DataSize == 0)
		{
			KER_HDMA_ERR("[HDMA]u32SrcVirAddr:0x%x, u32DataSize:0x%x \n", pstParam->u32SrcVirAddr, pstParam->u32DataSize);
			return ERR_INVAL;
		}
		memcpy( gpu8_HDMAMmapBuffAddr, ( void * )( pstParam->u32SrcVirAddr ), pstParam->u32DataSize );
	}

	if(pstParam->u32FuncMode == 3)
	{
		g_pstLeonMailboxReg->REG_LEON_IPC_MAILBOX0 = 0x1;
	}
	else
	{
		g_pstLeonMailboxReg->REG_LEON_IPC_MAILBOX0 = 0x0;
	}
	
	g_pstLeonMailboxReg->REG_LEON_IPC_MAILBOX3 = gu32_HDMAKernelBuffAddr; //setting table address
	g_pstLeonMailboxReg->REG_LEON_IPC_MAILBOX2 = (u32)gpu8_HDMAMmapBuffAddr;
	g_pstLeonCtlReg->REG_LEON_CTL_INI_2LEON = 0x0; // reset notify
	g_pstLeonCtlReg->REG_LEON_CTL_INI_2LEON = 0x1; // set notify to leon

	return ERR_NOERR;

}

#endif

/*-----------------------------------------------------------------------------*/
/* Debug Functions                                                             */
/*-----------------------------------------------------------------------------*/
#if ( HDMA_REG_MENU == ENABLE )
static ercode _dbgFun_HDMA_OPEN( u32 *pu32Par )
{
    return DRV_HDMA_Open();
}


static ercode _dbgFun_HDMA_SrcIncreDstFixed( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    u32 u32TestTimes = 0;
    u32 u32TestCount = pu32Par[1];
    bool infinite = ( ( u32TestCount == 0 ) ? TRUE : FALSE );

    while( infinite || ( u32TestTimes < u32TestCount ) ) {
        ret = _dbgFun_HDMA_SrcIncreDstFixed2( pu32Par );
        u32TestTimes++;
        KER_HDMA_DBG( "[SrcIncre, DstFixed] Test success! Run count: 0x%x\n", u32TestTimes );

        if( ret != ERR_NOERR ) {
            KER_HDMA_ERR( "Src Incre, Dst Fixed test fail!\n" );
            break;
        }
    }

    return ret;
}


static ercode _dbgFun_HDMA_SrcIncreDstFixed2( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    const u32 WORD_CNT = 256; // 1KB
    const u32 au32PATTERN_BASE[2] = {0x99990000, 0xAA550000};
    ST_DRV_HDMA_PARAMETER stParm;
    //vu32 *vu32OSDReg0xBC0D0118 = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x0118 );
    //vu32 *vu32OSDReg0xBC0D0110 = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x0110 );
    //vu32 *vu32OSDReg0xBC0D010C = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x010C );
    //vu32 *pu32DstVirAddr = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x0114 ); // OSD palette data port
    vu32 *vu32OSDReg_palette_ctrl = ( vu32 * )MA_KER_REG_REMAP( OSD_REG_BASE + 0x0410 );
    vu32 *vu32OSDReg_palette_index = ( vu32 * )MA_KER_REG_REMAP( OSD_REG_BASE + 0x0404 );
    vu32 *vu32OSDReg_palette_alloc = ( vu32 * )MA_KER_REG_REMAP( OSD_REG_BASE + 0x0420 );	
    vu32 *vu32OSDReg_palette_update = ( vu32 * )MA_KER_REG_REMAP( OSD_REG_BASE + 0x0428 );
    vu32 *pu32DstVirAddr = ( vu32 * )MA_KER_REG_REMAP( OSD_REG_BASE + 0x0408 ); // OSD palette data port
    u32 u32DstPhyAddr = ( OSD_REG_BASE + 0x0408 );
    u32 i;
    static u8 patternBaseIndex = 0;
    u32 testPattern[WORD_CNT];

    if( gstDRV_HDMAContext.s32Fd <= 0 ) {
        KER_HDMA_ERR( "DRV_HDMA is not initialized!\n" );
        ret = ERR_INVAL;
        goto TEST_FAIL;
    }

    if( pu32Par[0] == 0 ) {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_IMMEDIATELY;
        stParm.u32HLineCnt = 0;
    } else {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_H_LINE_COUNT;
        stParm.u32HLineCnt = 10;
    }

    // change PATTERN_BASE in every loop
    patternBaseIndex = ( ~patternBaseIndex ) & 0x1;

    // initialize test pattern
    for( i = 0; i < WORD_CNT; i++ ) {
        testPattern[i] = au32PATTERN_BASE[patternBaseIndex] + i;
    }

    stParm.enDMAMode = EN_DRV_HDMA_MODE_SRC_INCRE_DST_FIXED;
    stParm.u32SrcVirAddr = (( u32 )(uintptr_t)testPattern) & 0xFFFFFFFF;
    stParm.u32DstPhyAddr = u32DstPhyAddr;
    stParm.u32DataSize = WORD_CNT << 2;
    stParm.u32FuncMode = 1; // AXI to AHB

    // open OSD R/W data port
    //*vu32OSDReg0xBC0D0118 = 0x32100017;
    //*vu32OSDReg0xBC0D0110 = 0x00000000;
    //*vu32OSDReg0xBC0D010C = 0x40000000;
    *vu32OSDReg_palette_ctrl = 0x00000014;
    *vu32OSDReg_palette_index = 0x00000000;
    *vu32OSDReg_palette_alloc = 0x32100000;
    *vu32OSDReg_palette_update = 0x1;

    DRV_HdmaTransfer( &stParm );

    *vu32OSDReg_palette_ctrl = 0x00000014;
    *vu32OSDReg_palette_index = 0x00000000;
    *vu32OSDReg_palette_alloc = 0x32100000;
    *vu32OSDReg_palette_update = 0x1;

    // read back data for check.
    for( i = 0; i < WORD_CNT; i++ ) {
        if( *pu32DstVirAddr != testPattern[i] ) {
            KER_HDMA_DBG( "pu32DstAddr_SW addr: %x\n", ( u32 )pu32DstVirAddr );
            KER_HDMA_DBG( "read data: %x\n", *pu32DstVirAddr );
            KER_HDMA_DBG( "pattern data: %x\n", testPattern[i] );
            ret = ERR_INVAL;
            goto TEST_FAIL;
        }
    }

TEST_FAIL:
    return ret;
}

static ercode _dbgFun_HDMA_SrcIncreDstIncre( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    u32 u32TestTimes = 0;
    u32 u32TestCount = pu32Par[1];
    bool infinite = ( ( u32TestCount == 0 ) ? TRUE : FALSE );

    while( infinite || ( u32TestTimes < u32TestCount ) ) {
        ret = _dbgFun_HDMA_SrcIncreDstIncre2( pu32Par );
        u32TestTimes++;
        KER_HDMA_DBG( "[SrcIncre, DstIncre] Test success! Run count: 0x%x\n", u32TestTimes );

        if( ret != ERR_NOERR ) {
            KER_HDMA_ERR( "Src Incre, Dst Incre test fail!\n" );
            break;
        }
    }

    return ret;
}

static ercode _dbgFun_HDMA_SrcIncreDstIncre2( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    const u32 WORD_CNT = 256; // 1KB
    const u32 au32PATTERN_BASE[2] = {0x99990000, 0xAA550000};
    ST_DRV_HDMA_PARAMETER stParm;
    //vu32 *pu32DstVirAddr = ( vu32 * )BASE_REG_Phys2Virt( IMVQ_SRAM_BASE ); // SRAM virtual address
    vu32 *pu32DstVirAddr = ( vu32 * )MA_KER_REG_REMAP( IMVQ_SRAM_BASE ); // SRAM virtual address
    u32 u32DstPhyAddr = IMVQ_SRAM_BASE ;
    u32 i;
    static u8 patternBaseIndex = 0;
    u32 testPattern[WORD_CNT];

    if( gstDRV_HDMAContext.s32Fd <= 0 ) {
        KER_HDMA_ERR( "DRV_HDMA is not initialized!\n" );
        ret = ERR_INVAL;
        goto TEST_FAIL;
    }

    if( pu32Par[0] == 0 ) {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_IMMEDIATELY;
        stParm.u32HLineCnt = 0;
    } else {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_H_LINE_COUNT;
        stParm.u32HLineCnt = 10;
    }

    // change PATTERN_BASE in every loop
    patternBaseIndex = ( ~patternBaseIndex ) & 0x1;

    // initialize test pattern
    for( i = 0; i < WORD_CNT; i++ ) {
        testPattern[i] = au32PATTERN_BASE[patternBaseIndex] + i;
    }

    stParm.enDMAMode = EN_DRV_HDMA_MODE_BOTH_INCRE;
    stParm.u32SrcVirAddr = (( u32 )(uintptr_t)testPattern) & 0xFFFFFFFF;
    stParm.u32DstPhyAddr = u32DstPhyAddr;
    stParm.u32DataSize = WORD_CNT << 2;
    stParm.u32FuncMode = 1; // AXI to AHB

    //*( ( volatile u32 * )BASE_REG_Phys2Virt( IMVQ_SRAM_CTRL ) ) = 0x0; // IMVQ SRAM config
   *( ( volatile u32 * )MA_KER_REG_REMAP( IMVQ_SRAM_CTRL ) ) = 0x0;

    DRV_HdmaTransfer( &stParm );

    // read data back for check.
    for( i = 0; i < WORD_CNT; i++ ) {
        if( *( pu32DstVirAddr + i ) != testPattern[i] ) {
            KER_HDMA_DBG( "pu32DstAddr_SW addr: %x\n", ( u32 )pu32DstVirAddr );
            KER_HDMA_DBG( "read data: %x\n", *pu32DstVirAddr );
            KER_HDMA_DBG( "pattern data: %x\n", testPattern[i] );
            ret = ERR_INVAL;
            goto TEST_FAIL;
        }
    }

TEST_FAIL:
    return ret;
}

#if 0
static ercode _dbgFun_HDMA_SrcFixedDstFixed( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    u32 u32TestTimes = 0;
    u32 u32TestCount = pu32Par[1];
    bool infinite = ( ( u32TestCount == 0 ) ? TRUE : FALSE );

    while( infinite || ( u32TestTimes < u32TestCount ) ) {
        ret = _dbgFun_HDMA_SrcFixedDstFixed2( pu32Par );
        u32TestTimes++;
        DRV_HDMA_DBG( "[Src Fixed, Dst Fixed] Test success! Run count: 0x%x\n", u32TestTimes );

        if( ret != ERR_NOERR ) {
            DRV_HDMA_ERR( "Src Fixed, Dst Fixed test fail!\n" );
            break;
        }
    }

    return ret;
}

static ercode _dbgFun_HDMA_SrcFixedDstFixed2( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    const u32 WORD_CNT = 256; // 1KB
    const u32 au32PATTERN_BASE[2] = {0xBBBB0000, 0x55AA0000};
    ST_DRV_HDMA_PARAMETER stParm;
    vu32 *pu32FixedSrcReg = ( vu32 * )BASE_REG_Phys2Virt( 0xBC0C0014 );
    vu32 *vu32OSDReg0xBC0D0118 = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x0118 );
    vu32 *vu32OSDReg0xBC0D0110 = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x0110 );
    vu32 *vu32OSDReg0xBC0D010C = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x010C );
    vu32 *pu32DstVirAddr = ( vu32 * )BASE_REG_Phys2Virt( OSD_REG_BASE + 0x0114 ); // OSD palette data port
    u32 u32DstPhyAddr = 0x1C0D0114;
    u32 i;
    static u8 patternBaseIndex = 0;
    u32 testPattern[WORD_CNT];

    if( gstDRV_HDMAContext.s32Fd <= 0 ) {
        DRV_HDMA_ERR( "DRV_HDMA is not initialized!\n" );
        ret = ERR_INVAL;
        goto TEST_FAIL;
    }

    if( pu32Par[0] == 0 ) {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_IMMEDIATELY;
        stParm.u32HLineCnt = 0;
    } else {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_H_LINE_COUNT;
        stParm.u32HLineCnt = 10;
    }

    // change PATTERN_BASE in every loop
    patternBaseIndex = ( ~patternBaseIndex ) & 0x1;

    // initialize test pattern
    for( i = 0; i < WORD_CNT; i++ ) {
        testPattern[i] = au32PATTERN_BASE[patternBaseIndex];
    }

    *pu32FixedSrcReg = au32PATTERN_BASE[patternBaseIndex];

    stParm.enDMAMode = EN_DRV_HDMA_MODE_SRC_FIXED_DST_FIXED;
    stParm.u32DstPhyAddr = u32DstPhyAddr;
    stParm.u32DataSize = WORD_CNT << 2;
    stParm.u32FuncMode = 1; // AXI to AHB

    // open OSD R/W data port
    *vu32OSDReg0xBC0D0118 = 0x32100017;
    *vu32OSDReg0xBC0D0110 = 0x00000000;
    *vu32OSDReg0xBC0D010C = 0x40000000;

    DRV_HdmaTransfer( &stParm );

    // read back data for check.
    for( i = 0; i < WORD_CNT; i++ ) {
        if( *pu32DstVirAddr != testPattern[i] ) {
            DRV_HDMA_DBG( "pu32DstAddr_SW addr: %x\n", ( u32 )pu32DstVirAddr );
            DRV_HDMA_DBG( "read data: %x\n", *pu32DstVirAddr );
            DRV_HDMA_DBG( "pattern data: %x\n", testPattern[i] );
            ret = ERR_INVAL;
            goto TEST_FAIL;
        }
    }

TEST_FAIL:
    return ret;
}
#endif

static ercode _dbgFun_HDMA_SrcFixedDstIncre( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    u32 u32TestTimes = 0;
    u32 u32TestCount = pu32Par[1];
    bool infinite = ( ( u32TestCount == 0 ) ? TRUE : FALSE );

    while( infinite || ( u32TestTimes < u32TestCount ) ) {
        ret = _dbgFun_HDMA_SrcFixedDstIncre2( pu32Par );
        u32TestTimes++;
        KER_HDMA_DBG( "[SrcFixed, DstIncre] Test success! Run count: 0x%x\n", u32TestTimes );
	 
        if( ret != ERR_NOERR ) {
            KER_HDMA_ERR( "Src Fixed, Dst Incre test fail!\n" );
            break;
        }
    }

    return ret;
}


static ercode _dbgFun_HDMA_SrcFixedDstIncre2( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    const u32 WORD_CNT = 256; // 1KB
    const u32 au32PATTERN_BASE[2] = {0x99990000, 0xAA550000};
    ST_DRV_HDMA_PARAMETER stParm;
    //vu32 *pu32DstVirAddr = ( vu32 * )BASE_REG_Phys2Virt( IMVQ_SRAM_BASE ); // SRAM virtual address
    vu32 *pu32DstVirAddr = ( vu32 * )MA_KER_REG_REMAP( IMVQ_SRAM_BASE ); // SRAM virtual address
    u32 u32DstPhyAddr = IMVQ_SRAM_BASE ;
    u32 i;
    static u8 patternBaseIndex = 0;
    u32 testPattern[WORD_CNT];

    if( gstDRV_HDMAContext.s32Fd <= 0 ) {
        KER_HDMA_ERR( "DRV_HDMA is not initialized!\n" );
        ret = ERR_INVAL;
        goto TEST_FAIL;
    }

    if( pu32Par[0] == 0 ) {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_IMMEDIATELY;
        stParm.u32HLineCnt = 0;
    } else {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_H_LINE_COUNT;
        stParm.u32HLineCnt = 10;
    }

    // change PATTERN_BASE in every loop
    patternBaseIndex = ( ~patternBaseIndex ) & 0x1;

    // initialize test pattern
    for( i = 0; i < WORD_CNT; i++ ) {
        testPattern[i] = au32PATTERN_BASE[patternBaseIndex];
    }

    g_pstHDMACtrlReg->unXDMASrcData.val.u32Val = au32PATTERN_BASE[patternBaseIndex];

    stParm.enDMAMode = EN_DRV_HDMA_MODE_SRC_FIXED_DST_INCRE;
    stParm.u32DstPhyAddr = u32DstPhyAddr;
    stParm.u32DataSize = WORD_CNT << 2;
    stParm.u32FuncMode = 1; // AXI to AHB

    //*( ( volatile u32 * )BASE_REG_Phys2Virt( IMVQ_SRAM_CTRL ) ) = 0x0; // IMVQ SRAM config
    *( ( volatile u32 * )MA_KER_REG_REMAP( IMVQ_SRAM_CTRL ) ) = 0x0;

    DRV_HdmaTransfer( &stParm );

    // read data back for check.
    for( i = 0; i < WORD_CNT; i++ ) {
        if( *( pu32DstVirAddr + i ) != testPattern[i] ) {
            KER_HDMA_DBG( "pu32DstAddr_SW addr: %x\n", ( u32 )pu32DstVirAddr );
            KER_HDMA_DBG( "read data: %x\n", *pu32DstVirAddr );
            KER_HDMA_DBG( "pattern data: %x\n", testPattern[i] );
            ret = ERR_INVAL;
            goto TEST_FAIL;
        }
    }

TEST_FAIL:
    return ret;
}

static ercode _dbgFun_HDMA_DstAddrInDRAM( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    u32 u32TestTimes = 0;
    u32 u32TestCount = pu32Par[1];
    bool infinite = ( ( u32TestCount == 0 ) ? TRUE : FALSE );

    while( infinite || ( u32TestTimes < u32TestCount ) ) {
	if(0 == pu32Par[2])
	{
		KER_HDMA_DBG( "AHB Device: IMVQ SRAM \n");	
        	ret = _dbgFun_HDMA_DstAddrInDRAM2( pu32Par );
	}
	else if (1 == pu32Par[2])
	{
		KER_HDMA_DBG( "AHB Device: PQ IGAMMA data port  \n");	
        	ret = _dbgFun_HDMA_DstAddrInDRAM3( pu32Par );		
	}
	else
	{
		KER_HDMA_DBG( "No support AHB Device \n");	
		return ERR_NOERR;
	}

        u32TestTimes++;
        KER_HDMA_DBG( "[Dst addr in DRAM] Test success! Run count: 0x%x\n", u32TestTimes );

        if( ret != ERR_NOERR ) {
            KER_HDMA_ERR( "Dst addr in DRAM test fail!\n" );
            break;
        }
    }

    return ret;
}

static ercode _dbgFun_HDMA_DstAddrInDRAM2( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    const u32 WORD_CNT = 256; // 1KB
    const u32 au32PATTERN_BASE[2] = {0x99990000, 0xAA550000};
    ST_DRV_HDMA_PARAMETER stParm;
    //vu32 *pu32DstVirAddr = ( vu32 * )BASE_REG_Phys2Virt( IMVQ_SRAM_BASE ); // SRAM virtual address
    vu32 *pu32DstVirAddr = ( vu32 * )MA_KER_REG_REMAP( IMVQ_SRAM_BASE ); // SRAM virtual address
    u32 u32DstPhyAddr = IMVQ_SRAM_BASE;
    u32 i;
    static u8 patternBaseIndex = 0;
    u32 testPattern[WORD_CNT << 1]; // double buffer size

    if( gstDRV_HDMAContext.s32Fd <= 0 ) {
        KER_HDMA_ERR( "DRV_HDMA is not initialized!\n" );
        ret = ERR_INVAL;
        goto TEST_FAIL;
    }

    if( pu32Par[0] == 0 ) {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_IMMEDIATELY;
        stParm.u32HLineCnt = 0;
    } else {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_H_LINE_COUNT;
        stParm.u32HLineCnt = 10;
    }

    // change PATTERN_BASE in every loop
    patternBaseIndex = ( ~patternBaseIndex ) & 0x1;

    {
        u32 srcIndex = 0, destIndex = 0, dataIndex = 0;

        for( ; dataIndex < WORD_CNT; srcIndex += 2, destIndex += 4, dataIndex++ ) {
            testPattern[srcIndex] = au32PATTERN_BASE[patternBaseIndex] + dataIndex; // Data
            testPattern[srcIndex + 1] = u32DstPhyAddr + destIndex;                  // Destination address
        }

    }

    stParm.enDMAMode = EN_DRV_HDMA_MODE_DST_ADDR_IN_DRAM;
    stParm.u32SrcVirAddr = (( u32 )(uintptr_t)testPattern) & 0xFFFFFFFF;
    stParm.u32DstPhyAddr = u32DstPhyAddr;
    stParm.u32DataSize = WORD_CNT << 3;
    stParm.u32FuncMode = 1; // AXI to AHB

    //*( ( volatile u32 * )BASE_REG_Phys2Virt( IMVQ_SRAM_CTRL ) ) = 0x0; // IMVQ SRAM config
    *( ( volatile u32 * )MA_KER_REG_REMAP( IMVQ_SRAM_CTRL ) ) = 0x0;

    DRV_HdmaTransfer( &stParm );

    // read data back for check.
    for( i = 0; i < WORD_CNT; i++ ) {
        if( *( pu32DstVirAddr + i ) != testPattern[i << 1] ) {
            KER_HDMA_DBG( "pu32DstAddr_SW addr: %x\n", ( u32 )pu32DstVirAddr );
            KER_HDMA_DBG( "read data: %x\n", *pu32DstVirAddr );
            KER_HDMA_DBG( "pattern data: %x\n", testPattern[i] );
            ret = ERR_INVAL;
            goto TEST_FAIL;
        }
    }

TEST_FAIL:
    return ret;
}


void _set_PQ_Port(u32 u32Index)
{
	switch (u32Index)
	{
		case 0: 
			#ifdef PQ_658
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_658_SRAM_CTRL ) ) = 0x0000000C;
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = 0;
			#else
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = 0x0000000C;
			#endif
			break;
			
		case 1: 
			#ifdef PQ_658
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_658_SRAM_CTRL ) ) = 0x0000000a;
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = 0;
			#else
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = 0x0000000a;
			#endif
			break;
			
		case 2: 
			#ifdef PQ_658
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_658_SRAM_CTRL ) ) = 0x00000009;
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = 0;
			#else
			*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = 0x00000009;
			#endif
			break;
			
		default:
			break;
	}
}

u32 testPattern[1024 << 1]; // double buffer size
static ercode _dbgFun_HDMA_DstAddrInDRAM3( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    const u32 WORD_CNT = 1024; 
    const u32 au32PATTERN_BASE[2] = {0x99990000, 0xAA550000};
    ST_DRV_HDMA_PARAMETER stParm;
    #ifndef PQ_658
	vu32 *pu32DstVirAddr = ( vu32 * )MA_KER_REG_REMAP( PQ_SRAM_DATA_PORT );
    #endif
    u32 u32DstPhyAddr = PQ_SRAM_DATA_PORT;
    u32 i,j;
    static u8 patternBaseIndex = 0;
    //u32 testPattern[WORD_CNT << 1]; // double buffer size
    u32 srcIndex = 0, destIndex = 0, dataIndex = 0;
		
    if( gstDRV_HDMAContext.s32Fd <= 0 ) {
        KER_HDMA_ERR( "DRV_HDMA is not initialized!\n" );
        ret = ERR_INVAL;
        goto TEST_FAIL;
    }

    if( pu32Par[0] == 0 ) {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_IMMEDIATELY;
        stParm.u32HLineCnt = 0;
    } else {
        stParm.enTriggerMode = EN_HDMA_TRIGGER_MODE_H_LINE_COUNT;
        stParm.u32HLineCnt = 10;
    }

    for( ; dataIndex < WORD_CNT; srcIndex += 2, destIndex += 4, dataIndex++ ) {
        testPattern[srcIndex] = au32PATTERN_BASE[patternBaseIndex] + dataIndex; // Data
        testPattern[srcIndex + 1] = u32DstPhyAddr ;                  // Destination address
    }

    stParm.enDMAMode = EN_DRV_HDMA_MODE_DST_ADDR_IN_DRAM;
    stParm.u32SrcVirAddr = (( u32 )(uintptr_t)testPattern) & 0xFFFFFFFF;
    stParm.u32DstPhyAddr = u32DstPhyAddr;
    stParm.u32DataSize = WORD_CNT << 3;		//data and address are included 
    stParm.u32FuncMode = 1; // AXI to AHB
 
    *( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_ENABLE) ) = 0x2;	//gamma enable

    for(j=0; j<3; j++)
    {
		_set_PQ_Port(j);

		DRV_HdmaTransfer( &stParm );
    }

    // read data back for check.
    for(j=0; j<3; j++)
    {
		for( i = 0; i < WORD_CNT; i++ )
		{
			#ifdef PQ_658
				*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = i;
				*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_658_SRAM_CTRL ) ) = 1<<(26-j);
				if( *( ( volatile u32 * )MA_KER_REG_REMAP( PQ_658_SRAM_READ_DATA_PORT ) ) != (testPattern[i << 1]&0xFFF) )
				{
					KER_HDMA_DBG( "PQ_658:\n");
					KER_HDMA_DBG( "Channel ID: %d\n", i  );
					KER_HDMA_DBG( "read data: 0x%x\n", *( ( volatile u32 * )MA_KER_REG_REMAP( PQ_658_SRAM_READ_DATA_PORT ) ) );
					KER_HDMA_DBG( "pattern data: 0x%x\n", testPattern[i << 1] );
					ret = ERR_INVAL;
					goto TEST_FAIL;
				}
			#else
				*( ( volatile u32 * )MA_KER_REG_REMAP( PQ_SRAM_INDEX_PORT ) ) = (1<<(24+j) | (i<<8));
				if( (*( pu32DstVirAddr )&0xFFF) != (testPattern[i << 1]&0xFFF) )	//data port register base address is fixed
				{ 
					KER_HDMA_DBG( "Channel ID: %d\n", i  );
					KER_HDMA_DBG( "pu32DstAddr_SW addr: 0x%x\n", ( u32 )pu32DstVirAddr );
					KER_HDMA_DBG( "read data: 0x%x\n", *pu32DstVirAddr );
					KER_HDMA_DBG( "pattern data: 0x%x\n", ( testPattern[i << 1] & 0xFFF) );
					ret = ERR_INVAL;
					goto TEST_FAIL;
				}
			#endif
		}
    }	
TEST_FAIL:
    return ret;
}


static ercode _dbgFun_HDMA_TestAll( u32 *pu32Par )
{
    ercode ret = ERR_NOERR;
    u32 u32TestCount = pu32Par[1];
    bool infinite = ( ( u32TestCount == 0 ) ? TRUE : FALSE );
    u32 u32TestTimes = 0;

    gbTestAllEnable = TRUE;

    while( infinite || ( u32TestTimes < u32TestCount ) ) {
        if( _dbgFun_HDMA_SrcIncreDstFixed2( pu32Par ) != ERR_NOERR ) {
            KER_HDMA_ERR( "Src Incre, Dst Fixed test fail!\n" );
            ret = ERR_INVAL;
            break;
        };

        if( _dbgFun_HDMA_SrcIncreDstIncre2( pu32Par ) != ERR_NOERR ) {
            KER_HDMA_ERR( "Src Incre, Dst Incre test fail!\n" );
            ret = ERR_INVAL;
            break;
        };

#if 0
        if( _dbgFun_HDMA_SrcFixedDstFixed2( pu32Par ) != ERR_NOERR ) {
            DRV_HDMA_ERR( "Src Fixed, Dst Fixed test fail!\n" );
            ret = ERR_INVAL;
            break;
        };

#endif
        if( _dbgFun_HDMA_SrcFixedDstIncre2( pu32Par ) != ERR_NOERR ) {
            KER_HDMA_ERR( "Src Fixed, Dst Incre test fail!\n" );
            ret = ERR_INVAL;
            break;
        };

        if( _dbgFun_HDMA_DstAddrInDRAM2( pu32Par ) != ERR_NOERR ) {
            KER_HDMA_ERR( "Dst Addr In DRAM test fail!\n" );
            ret = ERR_INVAL;
            break;
        };

        u32TestTimes++;

        KER_HDMA_DBG( "[TestAll] Test success! Times: 0x%x\n", u32TestTimes );

        KER_HDMA_DBG( "------------------------------------------------------\n" );
    }

    return ret;
}


static ercode _dbgFun_HDMA_ShowRevision( u32 *pu32Par )
{
    //KER_HDMA_DBG( "%s", DRV_HDMA_VERSION );
    return 0;
}

#endif


K_MODULE_LICENSE( "Proprietary" );
K_MODULE_DESCRIPTION( "NOVATEK MICROELECTRONICS CORP - KHDMA MODULE" );
K_MODULE_AUTHOR( "MH Chen" );

VK_EXPORT_SYMBOL( KER_HDMA_DrvInit );
VK_EXPORT_SYMBOL( KER_HDMA_DrvExit );

K_INITREGISTER( KER_HDMA_DrvInit );
K_EXITREGISTER( KER_HDMA_DrvExit );

