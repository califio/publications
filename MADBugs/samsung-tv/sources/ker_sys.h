/*!
********************************************************************************
*  Copyright (c) Novatek Microelectronics Corp., Ltd. All Rights Reserved.
*  \file    ker_chip.h
*  \brief   util function
*  \project kernel mode driver
*  \chip    nt72682/nt72683
********************************************************************************
*/
#ifndef _KER_SYS_H
#define _KER_SYS_H

#ifdef  __cplusplus
extern "C" {
#endif

/*-----------------------------------------------------------------------------*/
/* Including Files                                                             */
/*-----------------------------------------------------------------------------*/
#include "def_type.h"
#include "../../src/ksys/sys_chp.h"

/*-----------------------------------------------------------------------------*/
/* Constant Definitions                                                        */
/*-----------------------------------------------------------------------------*/
#define VA_KER_SYS_MAJOR    NTKSYS_MAJOR
#define VA_KER_SYS_NAME     NTKSYS_NAME
#define VA_KER_SYS_IOC_ID   's'

#define MAX_UIO_IRQ			256

/*-----------------------------------------------------------------------------*/
/* Types Declarations - User/Kernel                                            */
/*-----------------------------------------------------------------------------*/


/*-----------------------------------------------------------------------------*/
/* Types Declarations - Kernel Only                                            */
/*-----------------------------------------------------------------------------*/
typedef enum _EN_SYS_MEM_TYPE
{
	EN_SYS_MEM_TYPE_PHYSICAL,
	EN_SYS_MEM_TYPE_PHYSICAL_CACHED,
//	EN_SYS_MEM_TYPE_LOGICAL,
//	EN_SYS_MEM_TYPE_VIRTUAL,

	EN_SYS_MEM_TYPE_MAX = 0x7fffffff

} EN_SYS_MEM_TYPE;


typedef enum _EN_SYS_CACHE_DIR
{
	EN_SYS_CACHE_DIR_TO_DEVICE,
	EN_SYS_CACHE_DIR_FROM_DEVICE,

	EN_SYS_CACHE_DIR_MAX = 0x7fffffff

} EN_SYS_CACHE_DIR;


typedef struct _ST_SYS_MEM_INFO
{
	EN_SYS_MEM_TYPE           enMemType;
	u32                       u32Index;             /**< ID of the mem information */
	u32                       u32Start;             /**< start address */
	u32                       u32Size;              /**< total size, 0 means ignore it */

} ST_SYS_MEM_INFO;

typedef struct _ST_SYS_MOD_INFO
{
	const char *prop_name;
	unsigned int base;
	unsigned int size;
	const char *prop_mem_protect;
	const char *prop_cma;

}ST_SYS_MOD_INFO;


typedef struct _ST_SYS_CACHE
{
	u32                       u32Size;              /**< size of the structure, in bytes. */
	u32                       u32Verion;            /**< version information of the structure */

	EN_SYS_CACHE_DIR          enDirect;
	u32                       u32Addr;
	u32                       u32DataSize;

} ST_SYS_CACHE;

typedef enum _EN_SYS_IRQ_FLAG
{
	EN_SYS_IRQ_FLAG_DISABLED,
	EN_SYS_IRQ_FLAG_SHARED,
	EN_SYS_IRQ_FLAG_MAX

} EN_SYS_IRQ_FLAG;
typedef enum _EN_SYS_SSC_PERIOD
{
	EN_SYS_SSC_PERIOD_20K,
	EN_SYS_SSC_PERIOD_25K,
	EN_SYS_SSC_PERIOD_27K,
	EN_SYS_SSC_PERIOD_30K,
	EN_SYS_SSC_PERIOD_32K,
	EN_SYS_SSC_PERIOD_33K,
	EN_SYS_SSC_PERIOD_40K
} EN_SYS_SSC_PERIOD;

typedef enum
{
    EN_SYS_SSC_LVDS_ONOFF,
    EN_SYS_SSC_LVDS_PERIOD,    // Period 20K, 30K, 40K
    EN_SYS_SSC_LVDS_AMPLITUDE,      // Amplitude 0.5%, 1%, 1.5%, 2%, 2.5%, 3%
    EN_SYS_SSC_DDR_ONOFF,
    EN_SYS_SSC_DDR_PERIOD,     // Period 20K, 30K, 40K
    EN_SYS_SSC_DDR_AMPLITUDE,  // Amplitude 0.5%, 1%, 1.5%, 2%
    EN_SYS_SSC_DDR_KVALUE_AMPLITUDE,
    EN_SYS_SSC_LVDS_KVALUE_AMPLITUDE,
    EN_SYS_SSC_DDR_KVALUE_CHANNEL,
    EN_SYS_SSC_MAX
} SY_SSC_k;

typedef struct _ST_SYS_SSC
{
	bool b8Enable;
	u8 u8FreqKHz;
	u8 u8PercentX10;
	u8 u8Channel;
} ST_SYS_SSC;

typedef struct _ST_SYS_IRQ_INFO
{
	char				acName[16];		/**< irq name */
	u32					u32Irq;			/**< irq number to serve as id*/
	EN_SYS_IRQ_FLAG		enIrqFlag;		/**< irq_flag */
	s32					s32Count;		/**< return interrupt count */
	void				*pParamAddr;	/**< send param address */
	u32					u32ParamVal;	/**< return param value */
} ST_SYS_IRQ_INFO;

typedef struct _ST_SYS_DDR_INFO
{
	u32					u32Total;
	u32					u32UsedPool;
	u32					u32FreePool;
	u32					u32BuffersPool;
	u32					u32CachedPool;

} ST_SYS_DDR_INFO;

typedef enum _EN_SYS_POWER_ON_EVENT
{
    EN_SYS_POWER_ON_EVENT_LAST_POWER_IS_ON = 0x01,
    EN_SYS_POWER_ON_EVENT_AC_POWER_TO_ON,

	//remote-controller wake up.
    EN_SYS_POWER_ON_EVENT_REMOTE_POWER_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N0_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N1_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N2_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N3_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N4_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N5_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N6_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N7_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N8_KEY,
    EN_SYS_POWER_ON_EVENT_RC_N9_KEY,
    EN_SYS_POWER_ON_EVENT_RC_PRG_UP_KEY,
    EN_SYS_POWER_ON_EVENT_RC_PRG_DOWN_KEY,
    EN_SYS_POWER_ON_EVENT_RC_IN_SRC_KEY,

	//front-panel wake up.
    EN_SYS_POWER_ON_EVENT_PANEL_POWER_KEY,
    EN_SYS_POWER_ON_EVENT_FP_PRG_UP_KEY,
    EN_SYS_POWER_ON_EVENT_FP_PRG_DOWN_KEY,
    EN_SYS_POWER_ON_EVENT_FP_VOL_UP_KEY, 		//touchpad
    EN_SYS_POWER_ON_EVENT_FP_VOL_DOWN_KEY, 	//touchpad
    EN_SYS_POWER_ON_EVENT_FP_TVAV_KEY, 		//touchpad
    EN_SYS_POWER_ON_EVENT_FP_IN_SRC_KEY,
    EN_SYS_POWER_ON_EVENT_FP_MENU_KEY,

    EN_SYS_POWER_ON_EVENT_VALID_SYNC_TO_ON,
    EN_SYS_POWER_ON_EVENT_WAKE_UP_TIME_MATCH,
    EN_SYS_POWER_ON_EVENT_CEC_POWER_ON,

    EN_SYS_POWER_ON_EVENT_SCART_PIN8_EXT1,
    EN_SYS_POWER_ON_EVENT_SCART_PIN8_EXT2,

    EN_SYS_POWER_ON_EVENT_CUSTOMER1,
    EN_SYS_POWER_ON_EVENT_CUSTOMER2,
    EN_SYS_POWER_ON_EVENT_CUSTOMER3,

	    EN_SYS_POWER_ON_EVENT_RESET,
    EN_SYS_POWER_ON_EVENT_UPGRADE,
    EN_SYS_POWER_ON_EVENT_WDT_RESET,
    EN_SYS_POWER_ON_EVENT_DBG_MENU,
	EN_SYS_POWER_ON_EVENT_RC_HOT_KEY=0x66,

    EN_SYS_POWER_ON_EVENT_TOTAL
} EN_SYS_POWER_ON_EVENT;
typedef enum _EN_SYS_PWR_KEY_MAPPING
{
	EN_SYS_POWER_ON_EVENT_MAPPING_REMOTE_POWER_KEY =0x30,
	EN_SYS_POWER_ON_EVENT_MAPPING_HOT_KEY = 0x31,
	EN_SYS_POWER_ON_EVENT_MAPPING_AC_POWER_TO_ON = 0x32,//0x30,

	EN_SYS_POWER_ON_EVENT_MAPPING_TOTAL
} EN_SYS_PWR_KEY_MAPPING;

/*-----------------------------------------------------------------------------*/
/* Command Definitions                                                         */
/*-----------------------------------------------------------------------------*/
#define KER_SYS_IOC_GET_CHP_INFO    _IOWR( VA_KER_SYS_IOC_ID, 0, ST_SYS_CHP_INFO )
#define KER_SYS_IOC_SET_MEM_INFO    _IOWR( VA_KER_SYS_IOC_ID, 1, ST_SYS_MEM_INFO )
#define KER_SYS_IOC_GET_MEM_INFO    _IOWR( VA_KER_SYS_IOC_ID, 2, ST_SYS_MEM_INFO )
#define KER_SYS_IOC_ADD_MEM_INFO    _IOWR( VA_KER_SYS_IOC_ID, 3, ST_SYS_MEM_INFO )
#define KER_SYS_IOC_GET_DDR_INFO    _IOWR( VA_KER_SYS_IOC_ID, 4, ST_SYS_DDR_INFO )
#define KER_SYS_IOC_GET_MOD_INFO    _IOWR( VA_KER_SYS_IOC_ID, 5, ST_SYS_MOD_INFO )

#define KER_SYS_IOC_INV_CACHE       _IOWR( VA_KER_SYS_IOC_ID,10, ST_SYS_CACHE )
#define KER_SYS_IOC_REG_IRQ    		_IOWR( VA_KER_SYS_IOC_ID,20, ST_SYS_IRQ_INFO )
#define KER_SYS_IOC_WAIT_IRQ    	_IOWR( VA_KER_SYS_IOC_ID,21, ST_SYS_IRQ_INFO )
#define KER_SYS_IOC_DONE_IRQ    	_IOWR( VA_KER_SYS_IOC_ID,22, ST_SYS_IRQ_INFO )
#define KER_SYS_IOC_UREG_IRQ    	_IOWR( VA_KER_SYS_IOC_ID,23, ST_SYS_IRQ_INFO )
#define KER_SYS_IOC_DEBUG_IRQ    	_IOWR( VA_KER_SYS_IOC_ID,24, ST_SYS_IRQ_INFO )
/*-----------------------------------------------------------------------------*/
/* Extern Global Variables                                                     */
/*-----------------------------------------------------------------------------*/
// DON'T export global variable here. Please use function to access them


/*-----------------------------------------------------------------------------*/
/* Interface Function Prototype                                                */
/*-----------------------------------------------------------------------------*/
int                  KER_SYS_DrvInit( void );
void                 KER_SYS_DrvExit( void );
int                  KER_SYS_IRQRequest( u32 u32Irq, void (*pfnIRQHandler)(int, void*), u32 u32IrqFlag, c8 *pc8Name, void *pvIRQParam, u8 u8FuncPriority, void* pParamAddr );
int                  KER_SYS_IRQFree( u32 u32Irq, void (*pfnIRQHandler)(int, void*), void *pvIRQParam, u8 u8FuncPriority );
EN_KER_SYS_CHIP_TYPE KER_SYS_GetChipType( void );
EN_KER_SYS_BOND_TYPE KER_SYS_GetBondType( void );
int KER_SYS_GetDateCode( void );
int _SYS_Get_UID(ST_SYS_CHP_INFO *pChpInfo);



#ifdef  __cplusplus
}
#endif

#endif

