/***************************************************************/
// DEBUG MACROS
#ifdef __DEBUG__
#define DEBUG_ERR(reason) (cerr << "Function " << __FUNCTION__ << ": Error ( " << reason << ")\n")
#else
#define DEBUG_ERR(reason) do{}while(0)
#endif
#define EXIT (exit(1))
#ifdef __DEBUG__
#define NETPERF_DEBUG(msg, ...) \
        printf("[%s] ", __FUNCTION__); \
        printf(msg, ##__VA_ARGS__); \
        printf("\n");
#else
#define NETPERF_DEBUG(msg, ...) do{}while(0)
#endif
#ifdef __DEBUG__
#define NETPERF_ASSERT(cond, msg, ...) \
    if (!(cond)) {  \
        printf("\u2192**NETPERF Assertion failed**: file (%s), function (%s), line (%d)\n", __FILE__, __FUNCTION__, __LINE__); \
        printf("\u2192"); \
        printf(msg, ##__VA_ARGS__); \
        exit(1); \
    }
#else
#define NETPERF_ASSERT(cond, msg, ...) do{}while(0)
#endif
#define PLAIN_ASSERT(cond, msg, ...) \
    if (!(cond)) { \
        printf("\u2192**Assertion failed**: file (%s), function (%s), line (%d)\n\n", __FILE__, __FUNCTION__, __LINE__); \
        printf(msg, ##__VA_ARGS__); \
        printf("\n"); \
        exit(1); \
    }
/***************************************************************/


