#include "HAL9000.h"
#include "ex_timer.h"
#include "iomu.h"
#include "thread_internal.h"

static struct _GLOBAL_TIMER_LIST m_globalTimerList;

STATUS
ExTimerInit(
    OUT     PEX_TIMER       Timer,
    IN      EX_TIMER_TYPE   Type,
    IN      QWORD           Time
    )
{
    STATUS status;

    if (NULL == Timer)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (Type > ExTimerTypeMax)
    {
        return STATUS_INVALID_PARAMETER2;
    }

    status = STATUS_SUCCESS;

    memzero(Timer, sizeof(EX_TIMER));

    Timer->Type = Type;
    if (Timer->Type != ExTimerTypeAbsolute)
    {
        // relative time

        // if the time trigger time has already passed the timer will
        // be signaled after the first scheduler tick
        Timer->TriggerTimeUs = IomuGetSystemTimeUs() + Time;
        Timer->ReloadTimeUs = Time;
    }
    else
    {
        // absolute
        Timer->TriggerTimeUs = Time;
    }

    BOOLEAN signaled = FALSE;
    ExEventInit(&Timer->TimerEvent, ExEventTypeNotification, signaled);

    //add timer to the list
    INTR_STATE dummyState;
    LockAcquire(&m_globalTimerList.TimerListLock, &dummyState);
    InsertOrderedList(&m_globalTimerList.TimerListHead, &Timer->TimerListElem, ExTimerCompareListElems, NULL);
    LockRelease(&m_globalTimerList.TimerListLock, dummyState);

    return status;
}

void
ExTimerStart(
    IN      PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = TRUE;
}

void
ExTimerStop(
    IN      PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    Timer->TimerStarted = FALSE;

    ExEventSignal(&Timer->TimerEvent);
}

void
ExTimerWait(
    INOUT   PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    if (Timer->TimerUninited)
    {
        return;
    }

    if(Timer -> TimerStarted)
        ExEventWaitForSignal(&Timer->TimerEvent);

    /*while (IomuGetSystemTimeUs() < Timer->TriggerTimeUs && Timer->TimerStarted)
    {
        ThreadYield();
    }*/
}

void
ExTimerUninit(
    INOUT   PEX_TIMER       Timer
    )
{
    ASSERT(Timer != NULL);

    ExTimerStop(Timer);

    Timer->TimerUninited = TRUE;


    //remove timer from global list
    INTR_STATE dummyState;
    LockAcquire(&m_globalTimerList.TimerListLock, &dummyState);
    RemoveEntryList(&Timer -> TimerListElem);
    LockRelease(&m_globalTimerList.TimerListLock, dummyState);
}

INT64
ExTimerCompareTimers(
    IN      PEX_TIMER     FirstElem,
    IN      PEX_TIMER     SecondElem
)
{
    return FirstElem->TriggerTimeUs - SecondElem->TriggerTimeUs;
}

STATUS 
(__cdecl ExTimerCheck)(
    IN   PLIST_ENTRY       TimerEntry,
    IN_OPT  PVOID Context
)
{   
    ASSERT(Context == NULL);
    PEX_TIMER Timer = CONTAINING_RECORD(TimerEntry, EX_TIMER, TimerListElem);
    if (IomuGetSystemTimeUs() >= Timer ->TriggerTimeUs && Timer ->TimerStarted)
        ExEventSignal(&Timer->TimerEvent);

    return STATUS_SUCCESS;
}


//initialize global list -> initialize lock and head of the list
void 
ExTimerSystemPreinit() {

    memset(&m_globalTimerList, 0, sizeof(_GLOBAL_TIMER_LIST));
    InitializeListHead(&m_globalTimerList.TimerListHead);
    LockInit(&m_globalTimerList.TimerListLock);
}

//function to pass to the InsertOrderedList in order to compare elems
INT64(__cdecl ExTimerCompareListElems)(
    IN PLIST_ENTRY t1, 
    IN PLIST_ENTRY t2, 
    IN_OPT  PVOID Context
    )
{
    ASSERT(t1 != NULL);
    ASSERT(t2 != NULL);
    ASSERT(Context == NULL);

    return ExTimerCompareTimers(CONTAINING_RECORD(t1, EX_TIMER, TimerListElem),CONTAINING_RECORD(t2, EX_TIMER, TimerListElem));
}

void ExTimerCheckAll() {
    INTR_STATE dummyState;
    LockAcquire(&m_globalTimerList.TimerListLock, &dummyState);
    ForEachElementExecute(&m_globalTimerList.TimerListHead, ExTimerCheck, NULL, FALSE);
    LockRelease(&m_globalTimerList.TimerListLock, dummyState);
}