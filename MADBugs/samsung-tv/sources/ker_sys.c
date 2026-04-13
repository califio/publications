/*!
********************************************************************************
*  Copyright (c) Novatek Microelectronics Corp., Ltd. All Rights Reserved.
*  \file    ker_sys.c
*  \brief   sys function
*  \project kernel mode driver
*  \chip    nt72682
********************************************************************************
*/
/*-----------------------------------------------------------------------------*/
/* Include Header Files                                                        */
/*-----------------------------------------------------------------------------*/
//! device
#include <vos/linux/fs.h>             /*! iminor, imajor */
#include <vos/linux/types.h>          /*! dev_t and related APIs.*/
#include <vos/linux/cdev.h>           /*! cdev_init, cdev_alloc, cdev_put, cdev_del, cdev_add, register_chrdev_region, unregister_chrdev_region, cdev_search_device */
#include <vos/linux/kdev_t.h>         /*! MAJOR, MINOR, MKDEV */
#include <vos/linux/module.h>         /*! THIS_MODULE */
#include <vos/linux/mm.h>             /*! put_page_testzero, get_user_pages, get_page */
#include <vos/linux/ioctl.h>          /*! _IO(), _IOR(), _IOW(), _IOWR() */
#include <vos/linux/delay.h>          /*! mdelay, udelay */
//! system call
#include <vos/linux/interrupt.h>      /*! request_irq, free_irq, disable_$rq, enable_irq, tasklet_init, tasklet_schedule, tasklet_kill, tasklet_disable_nosync */
#include <vos/linux/mm_types.h>       /*! io_remap_pfn_range, remap_pfn_range, pgprot_noncached */
#include <vos/linux/printk.h>         /*! prink */
#include <vos/linux/sched.h>          /*! schedule, schedule_timeout, schedule_timeout_uninterruptible, schedule_timeout_killable, send_sig, signal_pending, pid_alive, set_user_nice, _set_current_state, wake_up_process, find_task_by_pid_ns, find_task_by_vpid */
#include <vos/linux/semaphore.h>      /*! sema_init, down_trylock, up, down_interruptible, down */
#include <vos/linux/slab.h>           /*! kmalloc, kfree */
#include <vos/linux/wait.h>           /*! remove_wait_queue, init_waitqueue_head, add_wait_queue, wake_up, wake_up_interruptible, wait_event_interruptible, wait_event_timeout, __WAIT_QUEUE_HEAD_INITIALIZER, DECLARE_WAIT_QUEUE_HEAD, DECLARE_WAITQUEUE */
#include <vos/asm/atomic.h>           /*! atomic_read, atomic_set, atomic_add, atomic_sub, atomic_inc, atomic_dec, set_bit, clear_bit, test_bit, test_and_clear_bit, test_and_set_bit */
#include <vos/asm/io.h>               /*! virt_to_phys, phys_to_virt */
#include <vos/asm/uaccess.h>          /*! copy_from_user, copy_to_user */
//! driver
#include "ker_common.h"
#include "ker_err.h"
#include "ker_sys.h"
#include "ker_irq.h"
#include "ker_clk.h"
#include "nvt_fdt.h"
#include "nvt_mem.h"
#include "ker_clk.h"

#include <linux/version.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
#include <linux/of_irq.h>	// for  of_find_node_by_name, irq_of_parse_and_map
#include <linux/cpumask.h>
#endif

#if defined(CFG_ARCH_ARM_SERIES) && (CFG_ARCH_ARM_SERIES == 1)
#include "ker_dma_mapping.h"
#endif
#include "ker_pmi.h"
#include <vos/linux/jiffies.h> /*! jiffies_to_msecs, msecs_to_jiffies */

/*-----------------------------------------------------------------------------*/
/* Version Constant Definitions                                                */
/*-----------------------------------------------------------------------------*/
#define VA_SYS_VER_STRING     "0.0.1 [20160108]"

/*
Version 0.0.1 [20120827] ( Kevin )
- CHG : use virtual os api to replace original kernel system call. ( for multi-os purpose )
*/

/*-----------------------------------------------------------------------------*/
/* Local Constant Definitions                                                  */
/*-----------------------------------------------------------------------------*/
#ifndef MAX_UIO_MAPS
#define MAX_UIO_MAPS 32
#endif

#if !defined( IRQF_DISABLED )
#define IRQF_DISABLED 0
#endif

#define MA_SYS_READ_REG( addr ) (*(unsigned long volatile *)(addr))


#define pcc8FilePath			"/tmp/KeyEventInfo.bin"

/*-----------------------------------------------------------------------------*/
/* Local Types Declarations                                                    */
/*-----------------------------------------------------------------------------*/
static DEFINE_SPINLOCK(IRQ_spinlock);

typedef void  ( *FN_SYS_IRQ_HANDLER )( int iIrqNum, void *pvParam );

typedef struct _ST_SYS_IRQ_FUNCLIST
{
	u32                          u32StartTime;
	u32                          u32EndTime;
	u8                           u8FuncPriority;  /**< function priority */
	FN_SYS_IRQ_HANDLER           pfnFunc;	      /**< interrupt handler */
	void                        *pvFuncParam;
	struct _ST_SYS_IRQ_FUNCLIST *pstNext;
} ST_SYS_IRQ_FUNCLIST;

typedef struct _ST_SYS_IRQ_CONTEXT
{
	c8					*pcName;		/**< irq name */
	u32					u32Irq;			/**< irq number to serve as id*/
	s32					s32IrqFlag;		/**< irq_flag */
	s32					s32Count;		/**< return interrupt count */
	void				*pParamAddr;	/**< send param address */
	u32					u32ParamVal;	/**< return param value */

	atomic_t			event;			/**< record the interrupt count */
	wait_queue_head_t	wait;			/**< wait event */
	ST_SYS_IRQ_FUNCLIST	*pstFunclist;	/**< interrupt handler list in kernel mode */
} ST_SYS_IRQ_CONTEXT;

typedef struct _ST_SYS_IRQ_TABLE
{
	void*				pvIRQContext;	/**< depend on irq id to get irq context*/

} ST_SYS_IRQ_TABLE;

/*-----------------------------------------------------------------------------*/
/* Extern Global Variables                                                     */
/*-----------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------*/
/* Extern Function Prototype                                                   */
/*-----------------------------------------------------------------------------*/
#ifndef CONFIG_ARM64
extern void nvt_dma_flush_range(const void *, const void *);
#endif

/*-----------------------------------------------------------------------------*/
/* Local Function Protype                                                      */
/*-----------------------------------------------------------------------------*/
static long                  _SYS_UnlockIOC( struct vos_file * filp, unsigned int cmd, unsigned long arg );
static int                   _SYS_MMAP( struct vos_file * filp, struct vm_area_struct * vma );
static void                  _SYS_IRQNotify( int iIrq );
static irqreturn_t           _SYS_IRQHandler( int iIrq, void *pvDevId );
static int                   _SYS_IRQRegister( ST_SYS_IRQ_INFO *pstIrqinfo );
static int                   _SYS_IRQUnregister( ST_SYS_IRQ_INFO *pstIrqinfo );
static int                   _SYS_IRQWait( ST_SYS_IRQ_INFO *pstIrqinfo );
static int                   _SYS_IRQDone( ST_SYS_IRQ_INFO *pstIrqinfo );
static int                   _SYS_IRQDebug( ST_SYS_IRQ_INFO *pstIrqinfo );
static ST_SYS_IRQ_FUNCLIST * _SYS_IRQCreateNode( ST_SYS_IRQ_FUNCLIST *pstFunclist, u8 u8FuncPriority, void ( *pfnFunc )( int iIrqNum, void *pvIrqParam ), void *pvFuncParam, ST_SYS_IRQ_FUNCLIST *pstn );
static ST_SYS_IRQ_FUNCLIST * _SYS_IRQReleaseNode( ST_SYS_IRQ_FUNCLIST **ppstFunclist, u8 u8FuncPriority, void ( *pfnFunc )( int iIrqNum, void *pvIrqParam ), void *pvFuncParam );
static void                    _SYS_PmInit ( void );
static int _ker_sys_pmi_resume_p (struct device *dev);
static int _ker_sys_pmi_suspend_p (struct device *dev);
static bool _SYS_NotifyKeyEvent(void);
static void _SYS_AllIRQEnable( void );
static void _SYS_AllIRQDisable( void );

/*-----------------------------------------------------------------------------*/
/* Local Global Variables                                                      */
/*-----------------------------------------------------------------------------*/
/*Dynamic device number allocation*/
/* By default the module uses any available major, but it's possible to set it at load time to a specific number */
int KSYS_major = 0;
module_param(KSYS_major , int, S_IRUGO); /* r--r--r-- */
MODULE_PARM_DESC(KSYS_major, "Device major number");


static struct file_operations g_stSysFOPS =
{
	.owner          = VK_THIS_MODULE,
	.unlocked_ioctl = _SYS_UnlockIOC,
	.mmap           = _SYS_MMAP,
};

static struct cdev g_stSysCDEV =
{
	.kobj  = {
		.name = VA_KER_SYS_NAME,
	},
	.owner = VK_THIS_MODULE,
	.ops   = &g_stSysFOPS,
};
static bool8            g_b8Init = FALSE;
static ST_SYS_MEM_INFO  g_astMemInfo[MAX_UIO_MAPS];
static ST_SYS_DDR_INFO  g_astDDRInfo;
static struct semaphore g_stSemMemOp;
static struct semaphore g_stSemCchOp;

static ST_SYS_IRQ_TABLE g_stIrqTable[MAX_UIO_IRQ];
static ST_SYS_CHP_INFO  g_stChpInfo;
static ST_SYS_BOND_INFO  g_stBondInfo;
static struct class *nvt_sys_class;

/*-----------------------------------------------------------------------------*/
/* Interface Functions                                                         */
/*-----------------------------------------------------------------------------*/

static int _ker_sys_pmi_poweroff_late_p (struct device *dev) 
{
    unsigned long start_time = jiffies;
	
    vk_printk(KERN_INFO "@poweroff_late_time(in) %s\n", __FUNCTION__);
     
    vk_printk("[%s]Start \n", __FUNCTION__);
    //AHB GRPA
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TEMP_AVE,FALSE);     
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_APP_PARSER,FALSE);   
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_CI14,FALSE);		  
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_AC_DATA, FALSE);     
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_VIF,FALSE);          
    //AHB GRPE & K
    //AHB GRPC
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TS_MUX,FALSE);       
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_HDMA,FALSE);         
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_XDMA,FALSE);         
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_CRYPTO,FALSE);       
    //AHB GRPD
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER3,FALSE);       
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER2,FALSE);       
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_WDOG256FS,FALSE);    
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_WDOG,FALSE);         
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_HOUT,FALSE);         
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER1,FALSE);       
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER0,FALSE);       
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_SM,FALSE);           
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_DISP,FALSE);    
    //AHB GRPE
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_LED,FALSE);          
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TCONIR,FALSE);       
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TCON,FALSE);          
    //AXI GRPA
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ALP_PARSER_CORE,FALSE); 
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ALP_PARSER_BDGE,FALSE); 
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_AC_DATA,FALSE);         
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_VIF,FALSE);             
    //AXI GRPE&K
    //AXI GRPC
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_TS_MUX,FALSE);        
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_HDMA,FALSE);          
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_XDMA,FALSE);          
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ENCRYPT,FALSE);       
    //AXI GRPD
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ENCRYPT_HDCP,FALSE);  
    //GRP_A
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_TEMP_SENSOR,FALSE);  
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_RTC_ALP_PARSER,FALSE);    
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_ALP_PARSER,FALSE);   
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_CI14,FALSE);         
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_DVIF_VAR,FALSE);     
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_DVIF_108M,FALSE);    
    //GRP_B
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_TCON_SPI1,FALSE);    
    //GRP_C
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_ENCRYP_27M,FALSE);   
    //GRP_D
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_ADC_BIST_SIFADC,FALSE);  
    vk_printk(KERN_INFO "@poweroff_late_time/%s/%d/msec\n",
		  __FUNCTION__, jiffies_to_msecs(jiffies - start_time));
	
    return 0;
}

static int _ker_sys_pmi_powerresume_eayly_p (struct device *dev) 
{
    unsigned long start_time = jiffies;
	
    vk_printk(KERN_INFO "@powerresume_eayly__time(in) %s\n", __FUNCTION__);
    vk_printk("[%s]Start \n", __FUNCTION__);
    //AHB GRPA
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TEMP_AVE,TRUE);    
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_APP_PARSER,TRUE);  
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_CI14,TRUE);		
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_AC_DATA, TRUE);    
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_VIF,TRUE);         
    //AHB GRPE & K
    //AHB GRPC
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TS_MUX,TRUE);      
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_CRYPTO,TRUE);      
    //AHB GRPD
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER3,TRUE);      
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER2,TRUE);      
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_WDOG256FS,TRUE);   
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_WDOG,TRUE);        
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_HOUT,TRUE);        
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER1,TRUE);      
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TIMER0,TRUE);      
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_SM,TRUE);          
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_DISP,TRUE);        
    //AHB GRPE
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_LED,TRUE);         
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AHB_TCONIR,TRUE);      
    //AXI GRPA
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ALP_PARSER_CORE,TRUE);
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ALP_PARSER_BDGE,TRUE);
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_AC_DATA,TRUE);        
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_VIF,TRUE);            
    //AXI GRPE&K
    //AXI GRPC
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_TS_MUX,TRUE);       
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ENCRYPT,TRUE);      
    //AXI GRPD
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_AXI_ENCRYPT_HDCP,TRUE); 
    //GRP_A
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_TEMP_SENSOR,TRUE); 
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_RTC_ALP_PARSER,TRUE);   
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_ALP_PARSER,TRUE);  
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_CI14,TRUE);        
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_DVIF_VAR,TRUE);    
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_DVIF_108M,TRUE);   
    //GRP_B
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_TCON_SPI1,TRUE);   
    //GRP_C
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_ENCRYP_27M,TRUE);  
    //GRP_D
    KER_CLK_SetClockMask(EN_KER_CLK_MASK_CORE_ADC_BIST_SIFADC,TRUE); 
    vk_printk(KERN_INFO "@powerresume_eayly__time/%s/%d/msec\n",
		  __FUNCTION__, jiffies_to_msecs(jiffies - start_time));

    return 0;
}

static int _ker_sys_pmi_suspend_p (struct device *dev) 
{
	unsigned long start_time = jiffies;
	 vk_printk(KERN_INFO "@suspend(in) %s\n", __FUNCTION__);

	vk_printk("[%s]Start \n", __FUNCTION__);
    _SYS_AllIRQDisable();
 vk_printk(KERN_INFO "@suspend_time/%s/%d/msec\n",
		  __FUNCTION__, jiffies_to_msecs(jiffies - start_time));

	return 0;
}

static int _ker_sys_pmi_resume_p (struct device *dev) 
{
	int   iRetVal = 0;
    //pST_SYS_CHP_INFO pChipInfo = NULL;
    unsigned long start_time = jiffies;
 vk_printk(KERN_INFO "@resume(in) %s\n", __FUNCTION__);

	//! get chip type
	g_stChpInfo.enType = _SYS_GetType();
	vk_printk( "Chip id: 0x%x\n", g_stChpInfo.enType );
    //pChipInfo = &g_stChpInfo;
    //_SYS_GETChp_WaferInfo (pChipInfo);
	//vk_printk( "Lot num: %s\n", g_stChpInfo.u8LotID );
	//vk_printk( "Lot idx: %02d\n", g_stChpInfo.s32WaferIdx );
	//vk_printk( "WfPos X: %02d\n", g_stChpInfo.u16PosX);
	//vk_printk( "wfPos Y: %02d\n", g_stChpInfo.u16PosY );
    _SYS_AllIRQEnable();

 	if(FALSE == _SYS_NotifyKeyEvent())
	{
		//vk_printk("@@@@@@@@ Hot Key not ready\n");
		return iRetVal;
	}
 vk_printk(KERN_INFO "@resume_time/%s/%d/msec\n",
	  __FUNCTION__, jiffies_to_msecs(jiffies - start_time));
    return 0;
}

static int _ker_sys_suspend_p (struct device *dev)
{
	unsigned long start_time = jiffies;
	 vk_printk(KERN_INFO "@suspend(in) %s\n", __FUNCTION__);

    _SYS_AllIRQDisable();
	KER_PMI_Notify (KER_PMI_CLASS_SYSTEM, KER_PMI_CMD_SUSPEND);
 vk_printk(KERN_INFO "@suspend_time/%s/%d/msec\n",
	  __FUNCTION__, jiffies_to_msecs(jiffies - start_time));

	return 0;
}

static int _ker_sys_resume_p (struct device *dev)
{
	unsigned long start_time = jiffies;
 vk_printk(KERN_INFO "@resume(in) %s\n", __FUNCTION__);

	KER_PMI_Notify (KER_PMI_CLASS_SYSTEM, KER_PMI_CMD_RESUME);
    _SYS_AllIRQEnable();
 vk_printk(KERN_INFO "@resume_time/%s/%d/msec\n",
	  __FUNCTION__, jiffies_to_msecs(jiffies - start_time));

	return 0;
}

static const struct dev_pm_ops _ker_sys_pm_ops = {
	.resume = _ker_sys_resume_p,
	.suspend = _ker_sys_suspend_p,
};

static struct bus_type _ker_sys_bus = {    
	.name	= "ksys", 
	.pm		= &_ker_sys_pm_ops,
};

struct device _ker_sys_dev = {    
	.bus = &_ker_sys_bus,
};

static void _SYS_PmInit ( void )
{
#if (KER_PMI_CENTER == 0)
    bus_register( &_ker_sys_bus );

    _ker_sys_dev.init_name = "System";
    device_register( &_ker_sys_dev );
#else
    KER_PMI_ActScript_t stAct;
    memset( &stAct, 0 , sizeof( KER_PMI_ActScript_t ) );

    stAct.resume = _ker_sys_pmi_resume_p;
    stAct.suspend = _ker_sys_pmi_suspend_p;
    stAct.prepare = NULL;
    stAct.poweroff = _ker_sys_pmi_suspend_p;
    stAct.poweroff_late = _ker_sys_pmi_poweroff_late_p;
    stAct.power_resume = _ker_sys_pmi_resume_p;  
    stAct.power_resume_early = _ker_sys_pmi_powerresume_eayly_p;
    stAct.power_suspend = NULL;
    stAct.power_restore = NULL;


    KER_PMI_Install (    KER_PMI_CLASS_SYSTEM,
                        KER_PMI_CLASS_SYSTEM,
                        &stAct,
                        10,
                        0,
                        (void*)&_ker_sys_dev );
#endif


    return;
}

static char *nvt_sys_devnode(struct device *dev, umode_t *mode)
{
	*mode = 0666;
	return NULL;
}
int KER_SYS_DrvInit( void )
{
	int   iRetVal = 0;
	dev_t stDevNo;
	int i;
    pST_SYS_CHP_INFO pChipInfo = NULL;
    u32   u32UID[4] = {0, 0, 0, 0};

	//! check status
	if( g_b8Init == TRUE )
	{
		vk_printk( "can't init twice. (%d,%d)\n", VA_KER_SYS_MAJOR, 0 );
		return iRetVal;
	}

    nvt_bus_init();

	nvt_dt_init();

	//! ioremap register
	KER_REG_Init( KER_REG_MAP_START, KER_REG_MAP_SIZE );

	nvt_mem_init();

	//! get chip type
	g_stChpInfo.enType = _SYS_GetType();
	vk_printk( "Chip id: 0x%x\n", g_stChpInfo.enType );

    pChipInfo = &g_stChpInfo;
    _SYS_GETChp_WaferInfo (pChipInfo);
	vk_printk( "Lot num: %s\n", g_stChpInfo.u8LotID );

	//vk_printk( "Lot idx: %02d\n", g_stChpInfo.s32WaferIdx );
	//vk_printk( "WfPos X: %02d\n", g_stChpInfo.u16PosX);
	//vk_printk( "wfPos Y: %02d\n", g_stChpInfo.u16PosY );
    //_SYS_GetChip_ASMInfo(pChipInfo);
    //vk_printk( "Asm Inf: %04d,%c\n",  g_stChpInfo.u16DateCode, g_stChpInfo.u8AsmID);

	g_stChpInfo.iCurrMA = _SYS_GetChip_LeakageCurr(pChipInfo);
	vk_printk( "PwrCurr: %dmA\n", g_stChpInfo.iCurrMA );
    vk_printk( "Asm Inf: %04d,%c\n",  g_stChpInfo.u16DateCode, g_stChpInfo.u8AsmID);

    _SYS_Get_UID(pChipInfo);
    for (i=0; i<4; i++)
    {
        u32UID[i] =(u32)(g_stChpInfo.u8UID[i*4+0x00]) + 
            (u32)(g_stChpInfo.u8UID[i*4+0x01]<< 8) + 
            (u32)(g_stChpInfo.u8UID[i*4+0x02]<<16) + 
            (u32)(g_stChpInfo.u8UID[i*4+0x03]<<24);
    }    
    vk_printk( "UID Inf: %08x %08x %08x %08x\n", u32UID[0], u32UID[1], u32UID[2], u32UID[3]);

    // get package type
	vk_printk( "packet type: %x\n", NTCPE_Get_PacketType() );	

	//! get bond type
	g_stBondInfo.enType = _SYS_GetBond();
	vk_printk( "Bond type: 0x%x\n", g_stBondInfo.enType );

	//! initial mmap
	memset( &g_astMemInfo[0], 0, sizeof( ST_SYS_MEM_INFO ) * MAX_UIO_MAPS );

    for( i = 0; i < MAX_UIO_MAPS; i++ )
    {
    	g_astMemInfo[i].enMemType = EN_SYS_MEM_TYPE_MAX;
    	g_astMemInfo[i].u32Index  = i;
    }	

	vk_sema_init( &g_stSemMemOp, 1 );
	vk_sema_init( &g_stSemCchOp, 1 );

	//! make & register device
#if ( defined( CFG_DYNAMIC_ALLOC_DEV_NUM ) && ( CFG_DYNAMIC_ALLOC_DEV_NUM == 1 ) )
	if (0 == KSYS_major) 
	{
		/* auto select a major */
		iRetVal = alloc_chrdev_region(&stDevNo, 0, 1, VA_KER_SYS_NAME);
		KSYS_major = MAJOR(stDevNo);
	} 
	else 
	{
		/* use load time defined major number */
		stDevNo = VK_MKDEV(KSYS_major, 0);
		iRetVal = register_chrdev_region(stDevNo, 1, VA_KER_SYS_NAME);
	}
#else
	KSYS_major = VA_KER_SYS_MAJOR;
	stDevNo = VK_MKDEV( VA_KER_SYS_MAJOR, 0 );
	iRetVal = vk_register_chrdev_region( stDevNo, 1, VA_KER_SYS_NAME );

#endif
	if( iRetVal )
	{
		vk_printk( "can't register_chrdev_region (%d,%d)\n", VA_KER_SYS_MAJOR, 0 );
		return iRetVal;
	}

	vk_cdev_init( &g_stSysCDEV, &g_stSysFOPS );
	iRetVal = vk_cdev_add( &g_stSysCDEV, stDevNo, 1 );
	if (0 == iRetVal) {
		nvt_sys_class = class_create(THIS_MODULE, VA_KER_SYS_NAME);
		nvt_sys_class->devnode = nvt_sys_devnode;
		if (IS_ERR(nvt_sys_class)) {
			iRetVal = PTR_ERR(nvt_sys_class);
		} else {
				device_create(nvt_sys_class, NULL, stDevNo, NULL, VA_KER_SYS_NAME);
				
		}
	}

	if( iRetVal )
	{
		vk_unregister_chrdev_region( stDevNo, 1 );
		vk_printk( "can't cdev_add (%d,%d)\n", VA_KER_SYS_MAJOR, 0 );
		return iRetVal;
	}

	for( i = 0; i < MAX_UIO_IRQ; i++ )
	{
		g_stIrqTable[i].pvIRQContext = NULL;
	}

	//! change status
	g_b8Init = TRUE;

#if defined(KER_OS_LINUX)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 35))
	g_astDDRInfo.u32Total = totalram_pages;
#else
	g_astDDRInfo.u32Total = 0;
#endif
#endif


	for( i = 0; i < MAX_UIO_MAPS; i++ )
	{
		g_astMemInfo[i].u32Start = 0;
	}

#if (KER_PMI_CENTER == 0)
    bus_register(&_ker_sys_bus);    
    _ker_sys_dev.init_name = "system";
    device_register(&_ker_sys_dev);

#endif

#if 1
	_SYS_PmInit();

#else
	KER_PMI_ActScript_t stAct;

	stAct.resume = _ker_sys_pmi_resume_p;
		stAct.suspend = _ker_sys_pmi_suspend_p;
		stAct.prepare = NULL;	
		KER_PMI_Install (	KER_PMI_CLASS_SYSTEM,
				KER_PMI_CLASS_SYSTEM,
				&stAct,
				0,
				0,
				(void*)&_ker_sys_dev);

#endif
	if(FALSE == _SYS_NotifyKeyEvent())
	{
		//vk_printk("@@@@@@@@ Hot Key not ready\n");
		return iRetVal;
	}

    KER_SYS_ProcFS_Init();

	return iRetVal;
}


void KER_SYS_DrvExit( void )
{
	dev_t stDevNo;

	//! check status
	if( g_b8Init )
	{
		KER_REG_Term();

		stDevNo = VK_MKDEV( KSYS_major, 0 );
		vk_cdev_del( &g_stSysCDEV );
		vk_unregister_chrdev_region( stDevNo, 1 );
		g_b8Init = FALSE;
	}

	vk_sema_init( &g_stSemMemOp, 0 );
	vk_sema_init( &g_stSemCchOp, 0 );

    KER_SYS_ProcFS_Close();
}

EN_KER_SYS_CHIP_TYPE KER_SYS_GetChipType( void )
{
	return g_stChpInfo.enType;
}

EN_KER_SYS_BOND_TYPE KER_SYS_GetBondType( void )
{
	return g_stBondInfo.enType;
}

int KER_SYS_GetDateCode( void )
{
	return g_stChpInfo.u16DateCode;     // ex 1634, 1701, ...
}


VK_EXPORT_SYMBOL( KER_SYS_GetChipType );

int KER_SYS_IRQRequest( u32 u32Irq, void ( *pfnIRQHandler )( int, void* ), u32 u32IrqFlag, c8 *pc8Name, void *pvIRQParam, u8 u8FuncPriority, void* pParamAddr )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
	ST_SYS_IRQ_INFO stIrqinfo;
	int iret = 0;
	ST_SYS_IRQ_FUNCLIST *pstn;
    unsigned long irq_spinlock_flags;

	if ( u32IrqFlag != IRQF_DISABLED )
	{
		return -EINVAL;
	}

	strncpy( stIrqinfo.acName, pc8Name, 15 );
	stIrqinfo.u32Irq = u32Irq;
	stIrqinfo.enIrqFlag = EN_SYS_IRQ_FLAG_DISABLED;
	stIrqinfo.s32Count = 0;
	stIrqinfo.pParamAddr = pParamAddr;
	stIrqinfo.u32ParamVal = 0;

	if ( _SYS_IRQRegister( &stIrqinfo ) != 0 )
	{
		return -EINVAL;
	}

	// get context
	pstIRQContext = g_stIrqTable[u32Irq].pvIRQContext;
	pstn = ( ST_SYS_IRQ_FUNCLIST * )vk_kmalloc( sizeof( ST_SYS_IRQ_FUNCLIST ), GFP_KERNEL );

    spin_lock_irqsave(&IRQ_spinlock, irq_spinlock_flags);

	// if register OK, create node
	if ( pstIRQContext != NULL )
	{
		pstIRQContext->pstFunclist = _SYS_IRQCreateNode( pstIRQContext->pstFunclist,
									 u8FuncPriority,
									 pfnIRQHandler,
									 pvIRQParam,
									 pstn );
	}
	else
	{
		iret = -EINVAL;
	}

    spin_unlock_irqrestore(&IRQ_spinlock, irq_spinlock_flags);

	if ( iret == -EINVAL )
	{
		if ( pstn )
		{
			vk_kfree( pstn );
		}
	}

	return iret;
}
VK_EXPORT_SYMBOL( KER_SYS_IRQRequest );

int KER_SYS_IRQFree( u32 u32Irq, void ( *pfnIRQHandler )( int, void* ), void *pvIRQParam, u8 u8FuncPriority )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
	ST_SYS_IRQ_INFO stIrqinfo;
	int iret = 0;
    unsigned long irq_spinlock_flags;

    spin_lock_irqsave(&IRQ_spinlock, irq_spinlock_flags);

	// get context
	pstIRQContext = g_stIrqTable[u32Irq].pvIRQContext;

	if ( pstIRQContext != NULL )
	{
		pstIRQContext->pstFunclist = _SYS_IRQReleaseNode( &(pstIRQContext->pstFunclist),
									 u8FuncPriority,
									 pfnIRQHandler,
									 pvIRQParam );

		if ( pstIRQContext->pstFunclist == NULL )
		{
			// done irq
			pstIRQContext->s32Count = -1;
			vk_wake_up_interruptible( &pstIRQContext->wait );

			// unregister
			stIrqinfo.u32Irq = u32Irq;

			if ( _SYS_IRQUnregister( &stIrqinfo ) != 0 )
			{
				iret = -EFAULT;
			}
		}
	}
	else
	{
		iret = -EINVAL;
	}

    spin_unlock_irqrestore(&IRQ_spinlock, irq_spinlock_flags);

	return iret;
}
VK_EXPORT_SYMBOL( KER_SYS_IRQFree );
#ifndef CONFIG_ARM64
VK_EXPORT_SYMBOL( nvt_dma_flush_range );
#endif

bool _SYS_EW_LVDS_DDR_SSC(u8 eMode, u8 uValue)
{
    bool Ret = TRUE;
    SY_SSC_k eSSCMode;
    static ST_SYS_SSC LVDS = {false,0,0,0}, DDR = {false,0,0,0};
    UN_KER_CLK_SETTING stClkSetting;
    
	vk_printk("\n [%s] : eMode=%d, uValue=%d - Start \n", __FUNCTION__, eMode, uValue);

    eSSCMode = (SY_SSC_k)eMode;
	
	switch(eSSCMode)
	{
		case EN_SYS_SSC_LVDS_ONOFF:
		{
			if(uValue == 1) LVDS.b8Enable = TRUE;	/*DDR_ON*/
			if(uValue == 0) LVDS.b8Enable = FALSE;	/*DDR_OFF*/
			break;
		}
		case EN_SYS_SSC_LVDS_PERIOD:
		{
			switch(uValue)
			{
				case 2:/*20K*/
					LVDS.u8FreqKHz = 20;
					break;
				case 3:/*30K*/
					LVDS.u8FreqKHz = 30;
					break;
				case 4:/*40K*/
					LVDS.u8FreqKHz = 40;
					break;
				//case 6:/*60K*/LVDS.u8FreqKHz=60; break;
				default:
					Ret = FALSE;
			}
			break;
		}
		case EN_SYS_SSC_LVDS_AMPLITUDE:
		{
			switch(uValue)
			{
				case 0:/*  0%*/
					LVDS.u8PercentX10 = 0;
					break;
				case 1:/*0.5%*/
					LVDS.u8PercentX10 = 5;
					break;
				case 2:/*1.0%*/
					LVDS.u8PercentX10 = 10;
					break;
				case 3:/*1.5%*/
					LVDS.u8PercentX10 = 15;
					break;
				case 4:/*2.0%*/
					LVDS.u8PercentX10 = 20;
					break;
				case 5:/*2.5%*/
					LVDS.u8PercentX10 = 25;
					break;
				case 6:/*3.0%*/
					LVDS.u8PercentX10 = 30;
					break;
				default:
					Ret = FALSE;
			}
			break;
		}
		case EN_SYS_SSC_LVDS_KVALUE_AMPLITUDE:
		{
			uint8_t mod_val = uValue % 6;
			switch(mod_val)
			{
				case 0:/*3.0%*/
					LVDS.u8PercentX10 = 30;
					break;
				case 1:/*2.5%*/
					LVDS.u8PercentX10 = 25;
					break;
				case 2:/*2.0%*/
					LVDS.u8PercentX10 = 20;
					break;
				case 3:/*1.5%*/
					LVDS.u8PercentX10 = 15;
					break;
				case 4:/*1.0%*/
					LVDS.u8PercentX10 = 10;
					break;
				case 5:/*0.5%*/
					LVDS.u8PercentX10 = 5;
					break;
				default:
					Ret = FALSE;
			}
			break;
		}

		case EN_SYS_SSC_DDR_ONOFF:
		{
			vk_printk("\n [%s] : ON = %d \n", __FUNCTION__, uValue);
			if(uValue == 1) DDR.b8Enable = TRUE;	/*DDR_ON*/
			if(uValue == 0) DDR.b8Enable = FALSE;	/*DDR_OFF*/
			break;
		}

		case EN_SYS_SSC_DDR_PERIOD:
		{
			vk_printk("\n [%s] : freq = %d \n", __FUNCTION__, uValue);
			switch(uValue)
			{
				case EN_SYS_SSC_PERIOD_20K:/*20K*/
					DDR.u8FreqKHz = 20;
					break;
				case EN_SYS_SSC_PERIOD_25K:/*25K*/
					DDR.u8FreqKHz = 25;
					break;
				case EN_SYS_SSC_PERIOD_30K:/*30K*/
					DDR.u8FreqKHz = 30;
					break;
				case EN_SYS_SSC_PERIOD_40K:/*40K*/
					DDR.u8FreqKHz = 40;
					break;
					//case 6:/*60K*/DDR.u8FreqKHz=60; break;
				default:
					Ret = FALSE;
			}
			break;
		}
		case EN_SYS_SSC_DDR_AMPLITUDE:   	// Amplitude 0.5%, 1%, 1.5%, 2%
		{
			vk_printk("\n [%s] : percent = %d \n", __FUNCTION__, uValue);
			switch(uValue)
			{
                case 0:/*  0%*/
                    DDR.u8PercentX10 = 0;
                    break;
                case 1:/*0.1%*/
                    DDR.u8PercentX10 = 1;
                    break;
                case 2:/*0.2%*/
                    DDR.u8PercentX10 = 2;
                    break;
                case 3:/*0.3%*/
                    DDR.u8PercentX10 = 3;
                    break;
                case 4:/*0.4%*/
                    DDR.u8PercentX10 = 4;
                    break;
                case 5:/*0.5%*/
                    DDR.u8PercentX10 = 5;
                    break;
                case 6:/*0.6%*/
                    DDR.u8PercentX10 = 6;
                    break;
				default:
					Ret = FALSE;
			}
			break;
		}
		case EN_SYS_SSC_DDR_KVALUE_AMPLITUDE:
		{
			uint8_t mod_val = uValue % 5;
		 	vk_printk("\n [%s] : kvalue_percent = %d \n", __FUNCTION__, uValue);
			switch(mod_val)
			{
                case 0:/*  0.5%*/
					DDR.u8PercentX10 = 5;
                    break;
                case 1:/*0.4%*/
                    DDR.u8PercentX10 = 4;
                    break;
                case 2:/*0.3%*/
                    DDR.u8PercentX10 = 3;
                    break;
				case 3:/*0.2%*/
                    DDR.u8PercentX10 = 2;
                    break;
                case 4:/*0.1%*/
                    DDR.u8PercentX10 = 1;
                    break;
				default:
					Ret = FALSE;
			}
			break;
		}		
		case EN_SYS_SSC_MAX:
		{
			//set to MAX.
			LVDS.u8PercentX10 = 30;
			LVDS.u8FreqKHz = 40;

			DDR.u8PercentX10 = 20;
			DDR.u8FreqKHz = 40;
			break;
		}
		case EN_SYS_SSC_DDR_KVALUE_CHANNEL:
		{
			DDR.u8Channel = uValue;
			break;
		}
		default:
			Ret = FALSE;
			break;
	}

	if(Ret == TRUE)
	{
		if(eSSCMode == EN_SYS_SSC_MAX
			|| eSSCMode == EN_SYS_SSC_LVDS_ONOFF
			|| eSSCMode == EN_SYS_SSC_LVDS_PERIOD
			|| eSSCMode == EN_SYS_SSC_LVDS_AMPLITUDE)
		{
			#if 0
			printk("\n DRV_VID_SetLVDS_SSC-->[b8Enable = %s, u8FreqKHz = %d ,u8PercentX10 = %d] \n",LVDS.b8Enable? "Enable":"Disable",LVDS.u8FreqKHz,LVDS.u8PercentX10);
			if(VPL_SCLR_PANEL_SetPanelLvdsClockSpreadSpec(LVDS.b8Enable? EN_DRV_SCLR_DP_CLK_SSC_ON:EN_DRV_SCLR_DP_CLK_SSC_OFF, LVDS.u8FreqKHz, LVDS.u8PercentX10 ) == FALSE)
			{
				printk("\n set VPL_SCLR_PANEL_SetPanelLvdsClockSpreadSpec not success [b8Enable = %d, u8FreqKHz = %d ,u8PercentX10 = %d]\n"
								,LVDS.b8Enable,LVDS.u8FreqKHz,LVDS.u8PercentX10);
				Ret = FALSE;
			}
			#endif
            stClkSetting.stSSC.u32FreqKHz = LVDS.u8FreqKHz;
        	stClkSetting.stSSC.u32PercentX10 = LVDS.u8PercentX10;
            stClkSetting.stSSC.u32Enable = LVDS.b8Enable;

			KER_CLK_Update( EN_KER_CLK_MPLL_DP_SSC, stClkSetting );
		}
		if(eSSCMode == EN_SYS_SSC_MAX
			|| eSSCMode == EN_SYS_SSC_DDR_ONOFF
			|| eSSCMode == EN_SYS_SSC_DDR_PERIOD
			|| eSSCMode == EN_SYS_SSC_DDR_AMPLITUDE)
		{
			vk_printk(KERN_DEBUG "\n DRV_VID_SetDDR_SSC-->[b8Enable = %s, u8FreqKHz = %d ,u8PercentX10 = %d ,u8Channel = %d]\n",DDR.b8Enable? "Enable":"Disable",DDR.u8FreqKHz,DDR.u8PercentX10,DDR.u8Channel);
			vk_printk(KERN_DEBUG "\n DRV_SYS_SetDDRSSC EN_DRV_SYS_DDR_CH0 \n");
            stClkSetting.stSSC.u32FreqKHz = DDR.u8FreqKHz;
        	stClkSetting.stSSC.u32PercentX10 = DDR.u8PercentX10;
            stClkSetting.stSSC.u32Enable = DDR.b8Enable;
            stClkSetting.stSSC.u32Channel = DDR.u8Channel;
            //clk_update( EN_DRV_CLK_MPLL_DDR_SSC, stClkSetting );
            KER_CLK_Update( EN_KER_CLK_MPLL_DDR_SSC, stClkSetting );
		}
	}
	else
	{
		vk_printk(KERN_ERR "\n Setting not support [eMode = %d, value = %d]!!!!!\n",eMode,uValue);
		Ret = FALSE;
	}
    vk_printk(KERN_DEBUG "\n [%s] : eMode=%d, uValue=%d - End \n", __FUNCTION__, eMode, uValue);
    
	return Ret;
}

bool ndp_kvalue_setu32(const char *ssc_type, u8 val)
{
	u8 period = 0;
	vk_printk("[%s] ssc_type = %s, val = %d\n", __FUNCTION__, ssc_type, val);
	if (strcmp(ssc_type, "ssc_main_ddr") == 0)
	{
		if(val <= 4)
			period = (u8)EN_SYS_SSC_PERIOD_20K;
		else if(val >= 5 && val <= 9)
			period = (u8)EN_SYS_SSC_PERIOD_30K;
		else if(val == 10)
			period = (u8)EN_SYS_SSC_PERIOD_40K;
		else {
			vk_printk(KERN_ERR "\n [%s] - ssc_main_ddr wrong period val!!\n",__FUNCTION__);
			return FALSE;
		}

		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_KVALUE_CHANNEL, 0);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_PERIOD, period);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_KVALUE_AMPLITUDE, val);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_ONOFF, 1);
	}
	else if(strcmp(ssc_type, "ssc_sub_ddr") == 0)
	{
		if(val <= 4)
			period = (u8)EN_SYS_SSC_PERIOD_20K;
		else if(val >= 5 && val <= 9)
			period = (u8)EN_SYS_SSC_PERIOD_30K;
		else if(val == 10)
			period = (u8)EN_SYS_SSC_PERIOD_40K;
		else {
			vk_printk(KERN_ERR "\n [%s] - ssc_main_ddr wrong period val!!\n",__FUNCTION__);
			return FALSE;
		}

		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_KVALUE_CHANNEL, 1);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_PERIOD, period);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_KVALUE_AMPLITUDE, val);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_ONOFF, 1);
	}
	else if(strcmp(ssc_type, "ssc_lvds") == 0)
	{
		if(val <= 5)
			period = (u8)EN_SYS_SSC_PERIOD_20K;
		else if(val >= 6 && val <= 11)
			period = (u8)EN_SYS_SSC_PERIOD_30K;
		else if(val == 12)
			period = (u8)EN_SYS_SSC_PERIOD_40K;
		else {
			vk_printk(KERN_ERR"\n [%s] - ssc_main_ddr wrong period val!!\n",__FUNCTION__);
			return FALSE;
		}

		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_DDR_KVALUE_CHANNEL, 0);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_LVDS_PERIOD, period);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_LVDS_KVALUE_AMPLITUDE, val);
		_SYS_EW_LVDS_DDR_SSC(EN_SYS_SSC_LVDS_ONOFF, 1);
	}
	else
	{
		vk_printk(KERN_ERR "[%s] unknown ss_type!\n",__FUNCTION__);
		return FALSE;
	}

	return TRUE;
}
VK_EXPORT_SYMBOL( ndp_kvalue_setu32 );

/*-----------------------------------------------------------------------------*/
/* Module Functions                                                            */
/*-----------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------*/
/* Task Functions                                                              */
/*-----------------------------------------------------------------------------*/
/*-----------------------------------------------------------------------------*/
/* Local Functions                                                             */
/*-----------------------------------------------------------------------------*/
static long _SYS_UnlockIOC( struct vos_file * filp, unsigned int cmd, unsigned long arg )
{
	long            lError = ENOERR;
	int             i;
    u32             u32Idx = 0;
	ST_SYS_MEM_INFO stMemInfo;
	ST_SYS_DDR_INFO stDDRInfo;
	ST_SYS_MOD_INFO stModInfo;
	struct memory_node* pstModNode;


	switch( cmd )
	{
		case KER_SYS_IOC_GET_CHP_INFO:
		{
			if( vk_copy_to_user( ( void * )arg, ( void * )&g_stChpInfo, sizeof( ST_SYS_CHP_INFO ) ) != ENOERR )
			{
				return -EFAULT;
			}

			break;
		}
		case KER_SYS_IOC_GET_MOD_INFO:
		{
            		memset( &stModInfo, 0, sizeof( ST_SYS_MOD_INFO ) );
			if( vk_copy_from_user( ( void * )&stModInfo, ( void * )arg, sizeof( ST_SYS_MOD_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
                int len = strlen_user( stModInfo.prop_name );
                char *prop_name = NULL;
                if ( len == 0 )
                {
                    lError = -EINVAL;
                    break;
                }

                prop_name = vk_kmalloc( len * sizeof(char), GFP_KERNEL );
                if ( !prop_name )
                {
                    lError = -EFAULT;
                    break;
                }
                if( vk_copy_from_user( prop_name, stModInfo.prop_name, len * sizeof(char) ) != ENOERR )
                {
                    lError = -EFAULT;
                    vk_kfree( prop_name );
                    break;
                }

				pstModNode =(struct memory_node *) nvt_mem_find_node_by_name(prop_name);
                vk_kfree( prop_name );
				if (pstModNode ==NULL)
				{
					lError = -EFAULT;
				}
				else
				{
					stModInfo.base = pstModNode->property.base;
					stModInfo.size = pstModNode->property.size;

					if( vk_copy_to_user( ( void * )arg, ( void * )&stModInfo, sizeof( ST_SYS_MOD_INFO ) ) != ENOERR )
					{
						lError = -EFAULT;
					}
					else
					{
						lError = ENOERR;
					}
				}
			}
			break;
		}
		case KER_SYS_IOC_SET_MEM_INFO:
		{
			vk_down( &g_stSemMemOp );

            memset( &stMemInfo, 0, sizeof( ST_SYS_MEM_INFO ) );
            
			if( vk_copy_from_user( ( void * )&stMemInfo, ( void * )arg, sizeof( ST_SYS_MEM_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				u32Idx = stMemInfo.u32Index;

				if( u32Idx >= MAX_UIO_MAPS )
				{
					lError = -EFAULT;
				}
				else
				{
					g_astMemInfo[u32Idx].enMemType = stMemInfo.enMemType;
					g_astMemInfo[u32Idx].u32Index  = u32Idx;
					g_astMemInfo[u32Idx].u32Start  = stMemInfo.u32Start;
					g_astMemInfo[u32Idx].u32Size   = stMemInfo.u32Size;
					lError = ENOERR;
				}
			}

			vk_up( &g_stSemMemOp );
			break;
		}

		case KER_SYS_IOC_GET_MEM_INFO:
		{
			vk_down( &g_stSemMemOp );

            memset( &stMemInfo, 0, sizeof( ST_SYS_MEM_INFO ) );

			if( vk_copy_from_user( ( void * )&stMemInfo, ( void * )arg, sizeof( ST_SYS_MEM_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				u32Idx = stMemInfo.u32Index;

				if( u32Idx >= MAX_UIO_MAPS )
				{
					lError = -EFAULT;
				}
				else
				{
					stMemInfo.enMemType = g_astMemInfo[u32Idx].enMemType;
					stMemInfo.u32Index  = g_astMemInfo[u32Idx].u32Index;
					stMemInfo.u32Start  = g_astMemInfo[u32Idx].u32Start;
					stMemInfo.u32Size   = g_astMemInfo[u32Idx].u32Size;

					if( vk_copy_to_user( ( void * )arg, ( void * )&stMemInfo, sizeof( ST_SYS_MEM_INFO ) ) != ENOERR )
					{
						lError = -EFAULT;
					}
					else
					{
						lError = ENOERR;
					}
				}
			}

			vk_up( &g_stSemMemOp );
			break;
		}

		case KER_SYS_IOC_ADD_MEM_INFO:
		{
			vk_down( &g_stSemMemOp );

            memset( &stMemInfo, 0, sizeof( ST_SYS_MEM_INFO ) );

			if( vk_copy_from_user( ( void * )&stMemInfo, ( void * )arg, sizeof( ST_SYS_MEM_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				u32Idx = MAX_UIO_MAPS;

				/*! for multi process : check if the info exist or not? */
				for( i = 0; i < MAX_UIO_MAPS; i++ )
				{
					if( ( stMemInfo.enMemType == g_astMemInfo[i].enMemType ) &&
						( stMemInfo.u32Size == g_astMemInfo[i].u32Size ) &&
						( stMemInfo.u32Start == g_astMemInfo[i].u32Start ) )
					{
						u32Idx = i;
						break;
					}
				}

				if( u32Idx >= MAX_UIO_MAPS )
				{
					//! no info is found -> add one
					for( i = 0; i < MAX_UIO_MAPS; i++ )
					{
						if( g_astMemInfo[i].enMemType == EN_SYS_MEM_TYPE_MAX )
						{
							u32Idx = i;
							break;
						}
					}
				}

				if( u32Idx >= MAX_UIO_MAPS )
				{
					lError = -EFAULT;
				}
				else
				{
					stMemInfo.u32Index = u32Idx;
					g_astMemInfo[u32Idx].enMemType = stMemInfo.enMemType;
					g_astMemInfo[u32Idx].u32Index  = u32Idx;
					g_astMemInfo[u32Idx].u32Start  = stMemInfo.u32Start;
					g_astMemInfo[u32Idx].u32Size   = stMemInfo.u32Size;

					if( vk_copy_to_user( ( void * )arg, ( void * )&stMemInfo, sizeof( ST_SYS_MEM_INFO ) ) != ENOERR )
					{
						lError = -EFAULT;
					}
					else
					{
						lError = ENOERR;
					}
				}
			}

			vk_up( &g_stSemMemOp );
			break;
		}

		case KER_SYS_IOC_INV_CACHE:
		{
			ST_SYS_CACHE stCache;

			vk_down( &g_stSemCchOp );

            memset( &stCache, 0, sizeof( ST_SYS_CACHE ) );

			if( vk_copy_from_user( ( void * )&stCache, ( void * )arg, sizeof( ST_SYS_CACHE ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				if( stCache.u32DataSize > 0 && stCache.u32Addr > 0 )
				{
#if defined(CFG_ARCH_ARM_SERIES) && (CFG_ARCH_ARM_SERIES == 1)
                    void *pvVirtAddr = (void *)vk_ioremap_cached( stCache.u32Addr, stCache.u32DataSize );
                    if( pvVirtAddr != NULL )
                    {
                        #ifdef CONFIG_ARM64
                        nvt_dma_cache_sync( pvVirtAddr, stCache.u32DataSize, ( stCache.enDirect == EN_SYS_CACHE_DIR_FROM_DEVICE ) ? DMA_FROM_DEVICE : DMA_TO_DEVICE );
                        #else
                        MA_KER_HW_MEM_DMA_MAP( stCache.u32Addr, pvVirtAddr, stCache.u32DataSize, ( stCache.enDirect == EN_SYS_CACHE_DIR_FROM_DEVICE ) ? DMA_FROM_DEVICE : DMA_TO_DEVICE );
                        MA_KER_HW_MEM_DMA_UNMAP( stCache.u32Addr, pvVirtAddr, stCache.u32DataSize, ( stCache.enDirect == EN_SYS_CACHE_DIR_FROM_DEVICE ) ? DMA_FROM_DEVICE : DMA_TO_DEVICE );
                        #endif
                        vk_iounmap( ( void * )pvVirtAddr );
                        //pvVirtAddr = NULL;
                    }
#else
					if( stCache.enDirect == EN_SYS_CACHE_DIR_FROM_DEVICE )
					{
						vk_dma_cache_inv( ( unsigned long )stCache.u32Addr, ( unsigned long )stCache.u32DataSize );
					}
					else
					{
						vk_dma_cache_wback_inv( ( unsigned long )stCache.u32Addr, ( unsigned long )stCache.u32DataSize );
					}
#endif
					lError = ENOERR;
				}
				else
				{
					lError = -EFAULT;
				}
			}

			vk_up( &g_stSemCchOp );
			break;
		}

		case KER_SYS_IOC_GET_DDR_INFO:
		{
			vk_down( &g_stSemMemOp );

            memset( &stDDRInfo, 0, sizeof( ST_SYS_DDR_INFO ) );
			stDDRInfo.u32Total = g_astDDRInfo.u32Total;

			if( vk_copy_to_user( ( void * )arg, ( void * )&stDDRInfo, sizeof( ST_SYS_DDR_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}

			vk_up( &g_stSemMemOp );			
			break;
		}

		case KER_SYS_IOC_REG_IRQ:
		{
			ST_SYS_IRQ_INFO stIrqinfo;

            memset( &stIrqinfo, 0, sizeof( ST_SYS_IRQ_INFO ) );

			if( vk_copy_from_user( ( void * )&stIrqinfo, ( void * )arg, sizeof( ST_SYS_IRQ_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				if ( _SYS_IRQRegister( &stIrqinfo ) != 0 )
				{
					lError = -EFAULT;
				}
			}

			break;
		}

		case KER_SYS_IOC_UREG_IRQ:
		{
			ST_SYS_IRQ_INFO stIrqinfo;

            memset( &stIrqinfo, 0, sizeof( ST_SYS_IRQ_INFO ) );

			if( vk_copy_from_user( ( void * )&stIrqinfo, ( void * )arg, sizeof( ST_SYS_IRQ_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				if ( _SYS_IRQUnregister( &stIrqinfo ) != 0 )
				{
					lError = -EFAULT;
				}
			}

			break;
		}

		case KER_SYS_IOC_WAIT_IRQ:
		{
			ST_SYS_IRQ_INFO stIrqinfo;

            memset( &stIrqinfo, 0, sizeof( ST_SYS_IRQ_INFO ) );

			if( vk_copy_from_user( ( void * )&stIrqinfo, ( void * )arg, sizeof( ST_SYS_IRQ_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				if ( _SYS_IRQWait( &stIrqinfo ) != 0 )
				{
					lError = -EFAULT;
				}
			}

			if( vk_copy_to_user( ( void * )arg, ( void * )&stIrqinfo, sizeof( ST_SYS_IRQ_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				lError = ENOERR;
			}

			break;
		}

		case KER_SYS_IOC_DONE_IRQ:
		{
			ST_SYS_IRQ_INFO stIrqinfo;

            memset( &stIrqinfo, 0, sizeof( ST_SYS_IRQ_INFO ) );

			if( vk_copy_from_user( ( void * )&stIrqinfo, ( void * )arg, sizeof( ST_SYS_IRQ_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				if ( _SYS_IRQDone( &stIrqinfo ) != 0 )
				{
					lError = -EFAULT;
				}
			}

			if( vk_copy_to_user( ( void * )arg, ( void * )&stIrqinfo, sizeof( ST_SYS_IRQ_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				lError = ENOERR;
			}

			break;
		}

		case KER_SYS_IOC_DEBUG_IRQ:
		{
			ST_SYS_IRQ_INFO stIrqinfo;

            memset( &stIrqinfo, 0, sizeof( ST_SYS_IRQ_INFO ) );

			if( vk_copy_from_user( ( void * )&stIrqinfo, ( void * )arg, sizeof( ST_SYS_IRQ_INFO ) ) != ENOERR )
			{
				lError = -EFAULT;
			}
			else
			{
				if ( _SYS_IRQDebug( &stIrqinfo ) != 0 )
				{
					lError = -EFAULT;
				}
			}

			break;
		}

		default:
		{
			lError = -ENOTTY;
			break;
		}
	}

	return lError;
}


static int _SYS_MMAP( struct vos_file * filp, struct vm_area_struct * vma )
{
	unsigned long u32RequestedPages, u32ActualPages;
	int           iRetVal = 0, m = 0;

	if ( vma->vm_end < vma->vm_start )
	{
		return -EINVAL;
	}

	m = vma->vm_pgoff;

	if( m >= MAX_UIO_MAPS )
	{
		return -EINVAL;
	}

	if( g_astMemInfo[m].enMemType == EN_SYS_MEM_TYPE_MAX )
	{
		return -EINVAL;
	}

	u32RequestedPages = ( vma->vm_end - vma->vm_start ) >> PAGE_SHIFT;
	u32ActualPages    = ( ( g_astMemInfo[m].u32Start & ~PAGE_MASK ) + g_astMemInfo[m].u32Size + PAGE_SIZE - 1 ) >> PAGE_SHIFT;

	if( u32RequestedPages > u32ActualPages )
	{
		return -EINVAL;
	}

	vk_printk( "\n%s 0: vma start 0x%08X size 0x%08X pgoff 0x%08X\n",
			__func__,
			( unsigned int ) vma->vm_start,
			( unsigned int )( vma->vm_end - vma->vm_start ),
			( unsigned int ) vma->vm_pgoff );

	switch( g_astMemInfo[m].enMemType )
	{
		case EN_SYS_MEM_TYPE_PHYSICAL:
		{
			vma->vm_flags |= VM_IO | VM_DONTDUMP;
			vma->vm_page_prot = vk_pgprot_noncached( vma->vm_page_prot );
			iRetVal = vk_remap_pfn_range( vma, vma->vm_start, g_astMemInfo[m].u32Start >> PAGE_SHIFT, vma->vm_end - vma->vm_start, vma->vm_page_prot );
			break;
		}

		case EN_SYS_MEM_TYPE_PHYSICAL_CACHED:
		{
			vma->vm_flags |= VM_IO | VM_DONTDUMP;
			iRetVal = vk_remap_pfn_range( vma, vma->vm_start, g_astMemInfo[m].u32Start >> PAGE_SHIFT, vma->vm_end - vma->vm_start, vma->vm_page_prot );
			break;
		}

		default:
		{
			iRetVal = -EINVAL;
			break;
		}
	}

	return iRetVal;
}

static void _SYS_IRQNotify( int iIrq )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;

	pstIRQContext = g_stIrqTable[iIrq].pvIRQContext;

	if ( pstIRQContext != NULL )
	{
		vk_atomic_inc( &( pstIRQContext->event ) );
		vk_wake_up_interruptible( &( pstIRQContext->wait ) );

		//vk_printk("@\n");
	}
}

static irqreturn_t _SYS_IRQHandler( int iIrq, void *pvDevId )
{
	ST_SYS_IRQ_CONTEXT  *pstIRQContext = ( ST_SYS_IRQ_CONTEXT * )pvDevId;
	ST_SYS_IRQ_FUNCLIST *pstFuncItem;
    unsigned long irq_spinlock_flags;

    spin_lock_irqsave(&IRQ_spinlock, irq_spinlock_flags);
	if ( pstIRQContext != NULL )
	{

		// get interrupt flag value for audio
		if ( pstIRQContext->pParamAddr != 0 )
		{
			pstIRQContext->u32ParamVal = *( ( u32 volatile * )( pstIRQContext->pParamAddr ) );
		}
		else
		{
			pstIRQContext->u32ParamVal = 0;
		}

		// funclist need to update
		pstFuncItem = pstIRQContext->pstFunclist;

		while( pstFuncItem != NULL )
		{
			if ( pstFuncItem->pfnFunc != NULL )
			{
				pstFuncItem->pfnFunc( pstIRQContext->u32Irq, pstFuncItem->pvFuncParam );
			}
			pstFuncItem = pstFuncItem->pstNext;
		}

		_SYS_IRQNotify( pstIRQContext->u32Irq );
	}

    spin_unlock_irqrestore(&IRQ_spinlock, irq_spinlock_flags);
	return IRQ_HANDLED;
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
static char* _GetDefaultIrqName(u32 u32Irq)
{
	switch (u32Irq)
	{
		case EN_KER_IRQ_ID_DP:
			return "DpVsync";
#if NT_CHIP_REV_GTE(NT72172, REV_A)
		case EN_KER_IRQ_ID_POST_DP:
			return "PostDpVsync";
		case EN_KER_IRQ_ID_FRC_MEMC:
			return "PQ_FRC";
#endif
		case EN_KER_IRQ_ID_OSD_PLANE1:
			return "Plane1-OsdVsync";
		case EN_KER_IRQ_ID_OSD_PLANE2:
			return "Plane2-OsdVsync";
		case EN_KER_IRQ_ID_OSD_PLANE3:
			return "Plane3-OsdVsync";
		case EN_KER_IRQ_ID_TCON_LED:
			return "TconLed";
		case EN_KER_IRQ_ID_IP0:
			return "Ip0Vsync";
		case EN_KER_IRQ_ID_IP1:
			return "Ip1Vsync";
		case EN_KER_IRQ_ID_LBM:
			return "LbmNLine";
		case EN_KER_IRQ_ID_SUB_DP:
			return "SubDpVsync";
		case EN_KER_IRQ_ID_DP_OSD:
			return "PQHLine";
		default:
			return NULL;
	}
}
#endif

static s32 _GetDefaultIrqType( u32 u32Irq )
{
	s32 s32Type = -1;

	switch ( u32Irq )
	{
		case EN_KER_IRQ_ID_IP0:
		case EN_KER_IRQ_ID_IP1:
		case EN_KER_IRQ_ID_DP:
		case EN_KER_IRQ_ID_LBM:
		case EN_KER_IRQ_ID_SUB_DP:
#if NT_CHIP_REV_GTE(NT72172, REV_A)
		case EN_KER_IRQ_ID_FRC_MEMC:
		case EN_KER_IRQ_ID_POST_DP:
#endif
			s32Type = IRQF_TRIGGER_HIGH;
			break;

		case EN_KER_IRQ_ID_DP_OSD:
#if NT_CHIP_REV_GTE(NT72172, REV_A)
        case EN_KER_IRQ_ID_POST_DP_OSD:
#endif
#if !NT_CHIP_REV_GTE(NT72458, REV_A) && !NT_CHIP_REV_GTE(NT72171, REV_A)
		case EN_KER_IRQ_ID_OSD_TOP:
		case EN_KER_IRQ_ID_OSD_PLANE1:
		case EN_KER_IRQ_ID_OSD_PLANE2:
		case EN_KER_IRQ_ID_OSD_PLANE3:
#endif
			s32Type = IRQF_TRIGGER_RISING;
			break;
	}

	return s32Type;
}

static int _SYS_IRQRegister( ST_SYS_IRQ_INFO *pstIrqinfo )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	struct device_node* np = NULL;
	int IrqFromDtb;
	char* IrqName = NULL;
	int irq_affinity = 0;
#endif
	int iret = 0;

	// check parameter
	if ( pstIrqinfo->u32Irq >= MAX_UIO_IRQ || pstIrqinfo->u32Irq >= EN_KER_IRQ_ID_MAX )
	{
		iret = -EINVAL;
		goto out;
	}

	if ( pstIrqinfo->enIrqFlag >= EN_SYS_IRQ_FLAG_MAX )
	{
		iret = -EINVAL;
		goto out;
	}

	if ( _GetDefaultIrqType( pstIrqinfo->u32Irq ) < 0 )
	{
		iret = -EINVAL;
		vk_printk( "irq %d, irq type is unknown\n", pstIrqinfo->u32Irq );
		goto out;
	}

	if ( g_stIrqTable[pstIrqinfo->u32Irq].pvIRQContext != NULL )
	{
		//ret = -EEXIST;
		vk_printk( "irq %d exist\n", pstIrqinfo->u32Irq );
		goto out;
	}

	// create irq context
	pstIRQContext = vk_kmalloc( sizeof( ST_SYS_IRQ_CONTEXT ), GFP_KERNEL );

	if ( !pstIRQContext )
	{
		iret = -ENOMEM;
		goto out;
	}

	// init irq context
	pstIRQContext->pcName = pstIrqinfo->acName;
	pstIRQContext->u32Irq = pstIrqinfo->u32Irq;

	if ( pstIrqinfo->enIrqFlag == EN_SYS_IRQ_FLAG_DISABLED )
	{
		pstIRQContext->s32IrqFlag = IRQF_DISABLED;
	}
	else if ( pstIrqinfo->enIrqFlag == EN_SYS_IRQ_FLAG_SHARED )
	{
		pstIRQContext->s32IrqFlag = IRQF_DISABLED;	//IRQF_SHARED;
	}

	pstIRQContext->s32IrqFlag |= _GetDefaultIrqType( pstIrqinfo->u32Irq );

	pstIRQContext->pParamAddr = pstIrqinfo->pParamAddr;
	pstIRQContext->u32ParamVal = pstIrqinfo->u32ParamVal;

	pstIRQContext->s32Count = 0;
	vk_init_waitqueue_head( &( pstIRQContext->wait ) );
	vk_atomic_set( &( pstIRQContext->event ), 0 );
	pstIRQContext->pstFunclist = NULL;

	// store to irq_table
	g_stIrqTable[pstIRQContext->u32Irq].pvIRQContext = pstIRQContext;

	// register irq
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	IrqName = _GetDefaultIrqName(pstIRQContext->u32Irq);
	if (!IrqName)
		IrqName = pstIRQContext->pcName;

	np = of_find_node_by_name(NULL, IrqName);
	if (!np)
	{
		vk_printk("%s devicde node(%s) not found in dtb.bin\n", __func__, IrqName);
		goto error;
	}
	IrqFromDtb = irq_of_parse_and_map(np,0);

	iret = vk_request_irq( IrqFromDtb, _SYS_IRQHandler, pstIRQContext->s32IrqFlag, IrqName, pstIRQContext );
    of_property_read_u32(np, "interrupt-affinity", &irq_affinity);
    if (irq_affinity < num_online_cpus() && irq_affinity > 0)
    {
        irq_set_affinity_hint(IrqFromDtb, cpumask_of(irq_affinity));
    }
#else
	iret = vk_request_irq( pstIRQContext->u32Irq, _SYS_IRQHandler, pstIRQContext->s32IrqFlag, pstIRQContext->pcName, pstIRQContext );
#endif

	if ( iret )
	{
		vk_printk( "rquest_irq fail\n" );
		goto error;
	}

	return 0;

error:
	vk_kfree( pstIRQContext );
out:
	return iret;
}

static int _SYS_IRQUnregister( ST_SYS_IRQ_INFO *pstIrqinfo )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
	int iret = 0;

	// check parameter
	if ( pstIrqinfo->u32Irq >= MAX_UIO_IRQ || pstIrqinfo->u32Irq >= EN_KER_IRQ_ID_MAX )
	{
		iret = -EINVAL;
		return iret;
	}

	// get context
	pstIRQContext = g_stIrqTable[pstIrqinfo->u32Irq].pvIRQContext;

	if ( pstIRQContext != NULL )
	{
		// unregister irq
		if ( pstIRQContext->s32IrqFlag != -1 )
		{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
			struct device_node* np = NULL;
			int IrqFromDtb;
			char* IrqName = NULL;

			IrqName = _GetDefaultIrqName(pstIRQContext->u32Irq);
			if (!IrqName)
			{
				vk_printk("[ERROR] This interrupt does not exit in array data base, please do not use %s to free irq\n", __func__);
				iret = -EINVAL;
				return iret;
			}

			np = of_find_node_by_name(NULL, IrqName);
			if (!np)
			{
				vk_printk("%s devicde node(%s) not found in dtb.bin\n", __func__, IrqName);
				iret = -EINVAL;
				return iret;
			}

			IrqFromDtb = irq_of_parse_and_map(np,0);

            irq_set_affinity_hint(IrqFromDtb, NULL);
			vk_free_irq( IrqFromDtb, pstIRQContext );
#else
			vk_free_irq( pstIRQContext->u32Irq, pstIRQContext );
#endif
			pstIRQContext->s32IrqFlag = -1;
		}

		// term irq context

		// free irq context
		vk_kfree( pstIRQContext );

		// remove from irq_table
		g_stIrqTable[pstIrqinfo->u32Irq].pvIRQContext = NULL;
	}
	else
	{
		iret = -EFAULT;
	}

	return iret;
}

static int _SYS_IRQWait( ST_SYS_IRQ_INFO *pstIrqinfo )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
	VK_DECLARE_WAITQUEUE( wait, current );
	s32 s32EventCount;
	int iret = 0;

	// check parameter
	if ( pstIrqinfo->u32Irq >= MAX_UIO_IRQ || pstIrqinfo->u32Irq >= EN_KER_IRQ_ID_MAX )
	{
		iret = -EFAULT;
		return iret;
	}

	// get irq context from pstIrqinfo
	pstIRQContext = g_stIrqTable[pstIrqinfo->u32Irq].pvIRQContext;

	if ( pstIRQContext != NULL )
	{
		vk_add_wait_queue( &pstIRQContext->wait, &wait );

		do
		{
			vk_set_current_state( TASK_INTERRUPTIBLE );

			if ( pstIRQContext->s32Count == -1 )	// release wait condition
			{
				break;
			}

			s32EventCount = vk_atomic_read( &pstIRQContext->event );

			if ( s32EventCount != pstIRQContext->s32Count )
			{
				pstIRQContext->s32Count = s32EventCount;
				break;
			}

			if ( vk_signal_pending( current ) )
			{
				iret = -ERESTARTSYS;
				break;
			}

			vk_schedule();
		}
		while ( 1 );

		vk_set_current_state( TASK_RUNNING );
		vk_remove_wait_queue( &pstIRQContext->wait, &wait );

		// send irq context to pstIrqinfo
		pstIrqinfo->s32Count = pstIRQContext->s32Count;
		pstIrqinfo->u32ParamVal = pstIRQContext->u32ParamVal;
	}
	else
	{
		iret = -EFAULT;
	}

	return iret;
}

static int _SYS_IRQDone( ST_SYS_IRQ_INFO *pstIrqinfo )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
	int iret = 0;

	// check parameter
	if ( pstIrqinfo->u32Irq >= MAX_UIO_IRQ || pstIrqinfo->u32Irq >= EN_KER_IRQ_ID_MAX )
	{
		iret = -EFAULT;
		return iret;
	}

	// get irq context from pstIrqinfo
	pstIRQContext = g_stIrqTable[pstIrqinfo->u32Irq].pvIRQContext;

	if ( pstIRQContext != NULL )
	{
		pstIRQContext->s32Count = -1;
		vk_wake_up_interruptible( &pstIRQContext->wait );
	}
	else
	{
		iret = -EFAULT;
	}

	return iret;
}

static int _SYS_IRQDebug( ST_SYS_IRQ_INFO *pstIrqinfo )
{
	int iret = 0;
	ST_SYS_IRQ_CONTEXT *pstIRQContext;

	// check parameter
	if ( pstIrqinfo->u32Irq >= MAX_UIO_IRQ || pstIrqinfo->u32Irq >= EN_KER_IRQ_ID_MAX )
	{
		iret = -EFAULT;
		return iret;
	}

	pstIRQContext = g_stIrqTable[pstIrqinfo->u32Irq].pvIRQContext;
	if ( pstIRQContext != NULL )
	{
		if ( pstIRQContext->pParamAddr != 0 )
		{
			pstIRQContext->u32ParamVal = *( ( u32 volatile * )( pstIRQContext->pParamAddr ) );
		}
		else
		{
			pstIRQContext->u32ParamVal = 0;
		}
	}
	_SYS_IRQNotify( pstIrqinfo->u32Irq );

	return iret;
}

static ST_SYS_IRQ_FUNCLIST * _SYS_IRQCreateNode( ST_SYS_IRQ_FUNCLIST *pstFunclist, u8 u8FuncPriority, void ( *pfnFunc )( int iIrqNum, void *pvIrqParam ), void *pvFuncParam, ST_SYS_IRQ_FUNCLIST *pstn )
{
	ST_SYS_IRQ_FUNCLIST *pstk = pstFunclist;
	ST_SYS_IRQ_FUNCLIST *pstt = NULL;

	if ( pstn == NULL )
	{
		return pstFunclist;
	}

	pstn->u32StartTime = 0;
	pstn->u32EndTime = 0;
	pstn->u8FuncPriority = u8FuncPriority;
	pstn->pfnFunc = pfnFunc;
	pstn->pvFuncParam = pvFuncParam;
	pstn->pstNext = NULL;

	if ( pstFunclist == NULL )
	{
		return pstn;
	}
	else
	{
		if ( pstk->u8FuncPriority >= pstn->u8FuncPriority )
		{
			pstn->pstNext = pstk;
			return pstn;
		}
		else
		{
			while ( 1 )
			{
				if ( pstk->u8FuncPriority < pstn->u8FuncPriority )
				{
				}
				else if ( pstk->u8FuncPriority >= pstn->u8FuncPriority )
				{
					pstn->pstNext = pstt->pstNext; //insert_node(t, n);
					pstt->pstNext = pstn;
					return pstFunclist;
				}

				if ( pstk->pstNext == NULL )
				{
					pstn->pstNext = pstk->pstNext;	//insert_node(k, n);
					pstk->pstNext = pstn;
					return pstFunclist;
				}

				pstt = pstk;
				pstk = pstk->pstNext;
			}
		}
	}

	return 0;
}

static ST_SYS_IRQ_FUNCLIST * _SYS_IRQReleaseNode( ST_SYS_IRQ_FUNCLIST **ppstFunclist, u8 u8FuncPriority, void ( *pfnFunc )( int iIrqNum, void *pvIrqParam ), void *pvFuncParam )
{
    
	ST_SYS_IRQ_FUNCLIST *pstFunclist;	
	ST_SYS_IRQ_FUNCLIST *pstk;
	ST_SYS_IRQ_FUNCLIST *pstt;

	
	if( ppstFunclist == NULL )
	{
		return NULL;
	}
	
    
	pstFunclist = *ppstFunclist; 
	pstk = pstFunclist;
	pstt = NULL;

	if ( pstFunclist == NULL )
	{
	}
	else
	{
		if ( pstk->u8FuncPriority == u8FuncPriority && pstk->pfnFunc == pfnFunc )
		{
			*ppstFunclist = pstk->pstNext;
			pstFunclist = *ppstFunclist ; 		    		
			vk_kfree( pstk );
		}
		else
		{
			while( 1 )
			{
				if ( pstk->pstNext == NULL )
				{
					break;
				}

				pstt = pstk;
				pstk = pstk->pstNext;

				if ( pstk->u8FuncPriority == u8FuncPriority && pstk->pfnFunc == pfnFunc )
				{
					pstt->pstNext = pstt->pstNext->pstNext;	//remove_node(t);
					vk_kfree( pstk );
					break;
				}
			}
		}
	}

	return pstFunclist;
}

static void _SYS_AllIRQEnable( void )
{
    u32 u32Irq = 0;
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
	struct device_node* np = NULL;
	int IrqFromDtb;
	char* IrqName = NULL;
#endif
	int iret = 0;

    for ( u32Irq = 0 ; u32Irq < MAX_UIO_IRQ ; ++u32Irq )
    {
        if ( g_stIrqTable[u32Irq].pvIRQContext == NULL )
            continue;
        vk_printk("%s irq(%d)\n", __func__, u32Irq);

        pstIRQContext = g_stIrqTable[u32Irq].pvIRQContext;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
    	IrqName = _GetDefaultIrqName(pstIRQContext->u32Irq);
    	if (!IrqName)
    		IrqName = pstIRQContext->pcName;

    	np = of_find_node_by_name(NULL, IrqName);
    	if (!np)
    	{
    		vk_printk("%s devicde node(%s) not found in dtb.bin\n", __func__, IrqName);
    		continue;
    	}
    	IrqFromDtb = irq_of_parse_and_map(np,0);

    	vk_enable_irq( IrqFromDtb );
#else
    	//iret = vk_request_irq( pstIRQContext->u32Irq, _SYS_IRQHandler, pstIRQContext->s32IrqFlag, pstIRQContext->pcName, pstIRQContext );
        vk_enable_irq( pstIRQContext->u32Irq );
#endif
    }

	return;
}

static void _SYS_AllIRQDisable( void )
{
	ST_SYS_IRQ_CONTEXT *pstIRQContext;
	int iret = 0;
    u32 u32Irq = 0;

    for ( u32Irq = 0 ; u32Irq < MAX_UIO_IRQ ; ++u32Irq )
    {
        if ( g_stIrqTable[u32Irq].pvIRQContext == NULL )
            continue;

    	// get context
    	pstIRQContext = g_stIrqTable[u32Irq].pvIRQContext;
        vk_printk("%s irq(%d)\n", __func__, u32Irq);

		// unregister irq
		if ( pstIRQContext->s32IrqFlag != -1 )
		{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 18, 0))
			struct device_node* np = NULL;
			int IrqFromDtb;
			char* IrqName = NULL;

			IrqName = _GetDefaultIrqName(pstIRQContext->u32Irq);
			if (!IrqName)
			{
				vk_printk("[ERROR] This interrupt does not exit in array data base, please do not use %s to free irq\n", __func__);
				iret = -EINVAL;
				continue;
			}

			np = of_find_node_by_name(NULL, IrqName);
			if (!np)
			{
				vk_printk("%s devicde node(%s) not found in dtb.bin\n", __func__, IrqName);
				iret = -EINVAL;
				continue;
			}

			IrqFromDtb = irq_of_parse_and_map(np,0);

            vk_disable_irq( IrqFromDtb );
#else
            vk_disable_irq( pstIRQContext->u32Irq );
#endif
        	vk_init_waitqueue_head( &( pstIRQContext->wait ) );
        	vk_atomic_set( &( pstIRQContext->event ), 0 );
		}

    }

	return;
}

static struct file *_file_open( const char *path, int flags, int rights )
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs( get_ds() );
    filp = filp_open( path, flags, rights );
    set_fs( oldfs );

    if( IS_ERR( filp ) )
    {
        err = PTR_ERR( filp );
        return NULL;
    }

    return filp;
}

static int _file_write( struct file *file, unsigned long long offset, unsigned char *data, unsigned int size )
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs( get_ds() );

    ret = vfs_write( file, data, size, &offset );

    set_fs( oldfs );
    return ret;
}

static void _file_close( struct file *file )
{
    filp_close( file, NULL );
}

static bool _SYS_NotifyKeyEvent(void)
{
	EN_SYS_POWER_ON_EVENT KeyEvent;
	EN_SYS_PWR_KEY_MAPPING PwrKeyMap;
#if 1
	struct file *fpFile = NULL;
	u32 u32reg =0;
	
	u32reg = (MA_KER_REG_GET( 0xFC040210 ) & 0x0000FF00)>>8;		//mailbox flag0 is used in ROM code, use flag1 instead is better
	KeyEvent = u32reg;	
	PwrKeyMap = (u32reg == EN_SYS_POWER_ON_EVENT_RC_HOT_KEY)?EN_SYS_POWER_ON_EVENT_MAPPING_HOT_KEY: EN_SYS_POWER_ON_EVENT_MAPPING_REMOTE_POWER_KEY;


	fpFile = _file_open( pcc8FilePath, O_CREAT | O_WRONLY, 0 );


    if( fpFile == NULL )
    {
        //vk_printk( "<%s> Open %s fail.\n", __FUNCTION__, pcc8FilePath );
        return -1;
    }
	_file_write( fpFile, 0, (char *)&PwrKeyMap, 1 );
	//vk_printk("<%s> HotKey is %x \n",__FUNCTION__,u32reg);
	_file_close( fpFile );
	


#else
	struct file *fPtr = NULL;
	u32 u32reg =0;
	
	u32reg = MA_KER_REG_GET( 0xFC040210 ) & 0x000000FF;
	KeyEvent = u32reg;
#if 0// Ori
	switch (KeyEvent)
	{
		case EN_POWER_ON_EVENT_RC_HOT_KEY:
		{
			PwrKeyMap = EN_SYS_POWER_ON_EVENT_MAPPING_HOT_KEY;
			break;
		}
		default:
		{
			PwrKeyMap = EN_SYS_POWER_ON_EVENT_MAPPING_AC_POWER_TO_ON;
			break;
		}
	}

#else
	PwrKeyMap = (u32reg == EN_SYS_POWER_ON_EVENT_RC_HOT_KEY)?EN_SYS_POWER_ON_EVENT_MAPPING_HOT_KEY: EN_SYS_POWER_ON_EVENT_MAPPING_REMOTE_POWER_KEY;


#endif
	//printk("@@@@@@@@@@@@@ <%s> PwrKeyMap = %x \n", __FUNCTION__,PwrKeyMap);

	fPtr = KER_Nerve_FSOpen( pcc8FilePath, O_CREAT | O_WRONLY );
	if (!fPtr)	// File open check
	{	 
		//printk("<%s> Open file fail !!\n",__FUNCTION__);  
		return FALSE; 
	}
	else
	{
		//printk("<%s> Open file Successfully !\n",__FUNCTION__); 	   
	}

	KER_Nerve_FSWrite(fPtr, (char *)&PwrKeyMap, 1); 
	KER_Nerve_FSClose(fPtr);

#endif
	u32reg = MA_KER_REG_GET( 0xFC040210);
	u32reg &= 0xFFFF00FF; 
	MA_KER_REG_SET( 0xFC040210, u32reg);
	
	return TRUE;

}

/*-----------------------------------------------------------------------------*/
/* Kernel Mode Definiton                                                       */
/*-----------------------------------------------------------------------------*/
K_INITREGISTER( KER_SYS_DrvInit );
K_EXITREGISTER( KER_SYS_DrvExit );
K_MODULE_LICENSE    ( VA_MODULE_LICENSE );
K_MODULE_AUTHOR     ( VA_MODULE_AUTHOR );
K_MODULE_DESCRIPTION( "NOVATEK MICROELECTRONICS CORP - SYS MODULE" );


