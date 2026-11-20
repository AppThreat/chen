package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{
    AllocationStatePass,
    ExtentPass,
    GuardPass,
    MemoryApiPass,
    MemorySafetyFindingPass,
    MemorySemanticsPass,
    ValueOriginPass
}
import io.shiftleft.semanticcpg.language.*

/** MS-ALLOC-005..009: the deallocation of the wrong thing and the uncontrolled allocation size.
  * Every positive is a classic CWE-761/590/762/789/680 shape; every negative is its good pair.
  */
class WrongDeallocationRuleTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |/* the CWE-761 shape: free of an offset pointer, and of non-heap storage */
    |void bad_free_offset(const char *userInput)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    strncpy(p, userInput, 63);
    |    p[63] = 0;
    |    p = p + 4;
    |    free(p);
    |}
    |
    |void good_free_original(const char *userInput)
    |{
    |    char *p = (char *)malloc(64);
    |    char *cursor;
    |    if (p == NULL) return;
    |    strncpy(p, userInput, 63);
    |    cursor = p + 4;
    |    (void)cursor;
    |    free(p);
    |}
    |
    |/* the Juliet CWE-761 shape: the walk moves the pointer, the free follows the walk */
    |void bad_walk_then_free(const char *userInput)
    |{
    |    char *data = (char *)malloc(64);
    |    if (data == NULL) exit(-1);
    |    strncpy(data, userInput, 63);
    |    data[63] = 0;
    |    for (; *data != '\0'; data++)
    |    {
    |        if (*data == 'x') break;
    |    }
    |    free(data);
    |}
    |
    |void good_walk_a_copy(const char *userInput)
    |{
    |    char *data = (char *)malloc(64);
    |    char *cursor;
    |    if (data == NULL) exit(-1);
    |    strncpy(data, userInput, 63);
    |    data[63] = 0;
    |    cursor = data;
    |    for (; *cursor != '\0'; cursor++)
    |    {
    |        if (*cursor == 'x') break;
    |    }
    |    free(data);
    |}
    |
    |/* a walk over a pointer no allocation in this frame produced: where the walk
    |   started is the caller's contract, and the release keeps out of it */
    |void silent_walk_then_free(char *data)
    |{
    |    for (; *data != '\0'; data++)
    |    {
    |        if (*data == 'x') break;
    |    }
    |    free(data);
    |}
    |
    |/* the Juliet CWE-415 shape: the suite marks the first release too */
    |void bad_double_free(void)
    |{
    |    char *p = (char *)malloc(100);
    |    if (p == NULL) exit(-1);
    |    free(p);
    |    free(p);
    |}
    |
    |void good_free_elements_then_container(char **elem, unsigned long n)
    |{
    |    unsigned long i;
    |    for (i = 0; i < n; i++) free(elem[i]);
    |    free(elem);
    |}
    |
    |static int badStatic = 0;
    |static void staticSink(char *data)
    |{
    |    if (badStatic) free(data);
    |}
    |void bad_static_flag_sink(void)
    |{
    |    char *data = (char *)malloc(100);
    |    if (data == NULL) exit(-1);
    |    free(data);
    |    badStatic = 1;
    |    staticSink(data);
    |}
    |
    |void good_static_flag_other_pointer(void)
    |{
    |    char *data = (char *)malloc(100);
    |    char *other = (char *)malloc(100);
    |    if (data == NULL || other == NULL) exit(-1);
    |    free(data);
    |    badStatic = 1;
    |    staticSink(other);
    |}
    |
    |static char *releasedSource(char *data)
    |{
    |    data = (char *)malloc(100);
    |    if (data == NULL) exit(-1);
    |    free(data);
    |    return data;
    |}
    |void bad_source_returns_released(void)
    |{
    |    char *data = NULL;
    |    data = releasedSource(data);
    |    free(data);
    |}
    |
    |static char *liveSource(char *data)
    |{
    |    data = (char *)malloc(100);
    |    if (data == NULL) exit(-1);
    |    return data;
    |}
    |void good_source_returns_live(void)
    |{
    |    char *data = NULL;
    |    data = liveSource(data);
    |    free(data);
    |}
    |
    |static void pointerSink(char *data)
    |{
    |    free(data);
    |}
    |void bad_pointer_sink(void)
    |{
    |    void (*funcPtr)(char *) = pointerSink;
    |    char *data = (char *)malloc(100);
    |    if (data == NULL) exit(-1);
    |    free(data);
    |    funcPtr(data);
    |}
    |
    |/* Juliet's variant 31: the second release frees a copy of the same pointer */
    |void bad_double_free_through_copy(void)
    |{
    |    char *data = (char *)malloc(100);
    |    if (data == NULL) exit(-1);
    |    free(data);
    |    {
    |        char *dataCopy = data;
    |        char *data = dataCopy;
    |        free(data);
    |    }
    |}
    |
    |void release_it(char *q)
    |{
    |    free(q);
    |}
    |
    |/* the first release freed the old block: the double free is the callee's and the last one */
    |void bad_rebound_then_released(void)
    |{
    |    char *p = (char *)malloc(8);
    |    if (p == NULL) exit(-1);
    |    free(p);
    |    p = (char *)malloc(8);
    |    if (p == NULL) exit(-1);
    |    release_it(p);
    |    free(p);
    |}
    |
    |void good_free_once(void)
    |{
    |    char *p = (char *)malloc(100);
    |    if (p == NULL) exit(-1);
    |    free(p);
    |}
    |
    |void bad_free_static(void)
    |{
    |    static char buf[64];
    |    free(buf);
    |}
    |
    |void bad_free_string_literal(void)
    |{
    |    char *p = "literal";
    |    free(p);
    |}
    |
    |void bad_free_stack(void)
    |{
    |    char buf[32];
    |    free(buf);
    |}
    |
    |void bad_free_address_of_local(void)
    |{
    |    int x = 1;
    |    int *q = &x;
    |    free(q);
    |}
    |
    |void good_free_heap(void)
    |{
    |    char *p = (char *)malloc(8);
    |    if (p == NULL) return;
    |    free(p);
    |}
    |
    |""".stripMargin,
    "wrongfree.c"
  )
      .moreCode(
        """
    |#include <stdlib.h>
    |
    |/* the CWE-762 shapes: a cross-family mismatch, and an array allocation
    |   released by the scalar form (and the reverse). A .cpp file - the C
    |   parser reads `delete` as a bare call and the operator forms never
    |   appear. */
    |void bad_mismatched_malloc_delete(void)
    |{
    |    int *p = (int *)malloc(sizeof(int) * 16);
    |    delete p;
    |}
    |
    |void bad_mismatched_new_free(void)
    |{
    |    int *p = new int(5);
    |    free(p);
    |}
    |
    |void good_matched_new_delete(void)
    |{
    |    int *p = new int(5);
    |    delete p;
    |}
    |
    |void bad_array_new_scalar_delete(void)
    |{
    |    char *p = new char[16];
    |    delete p;
    |}
    |
    |void bad_scalar_new_array_delete(void)
    |{
    |    int *p = new int(5);
    |    delete[] p;
    |}
    |
    |void good_matched_array_new_delete(void)
    |{
    |    char *p = new char[16];
    |    delete[] p;
    |}
    |""".stripMargin,
        "mismatch.cpp"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |
    |/* the Juliet CWE-789 / CWE-680 shapes over C++ new[] and scanf-filled sizes */
    |void bad_new_count_lower_bound(void)
    |{
    |    size_t data = 0;
    |    char inputBuffer[20] = "";
    |    if (fgets(inputBuffer, 20, stdin) != NULL) data = strtoul(inputBuffer, NULL, 0);
    |    if (data > strlen("hello"))
    |    {
    |        char *p = new char[data];
    |        strcpy(p, "hello");
    |        delete[] p;
    |    }
    |}
    |
    |void good_new_count_capped(void)
    |{
    |    size_t data = 0;
    |    char inputBuffer[20] = "";
    |    if (fgets(inputBuffer, 20, stdin) != NULL) data = strtoul(inputBuffer, NULL, 0);
    |    if (data > strlen("hello") && data < 1000)
    |    {
    |        char *p = new char[data];
    |        strcpy(p, "hello");
    |        delete[] p;
    |    }
    |}
    |
    |void bad_scanf_size_after_init(void)
    |{
    |    size_t data = 0;
    |    fscanf(stdin, "%zu", &data);
    |    char *p = (char *)malloc(data * sizeof(char));
    |    if (p) free(p);
    |}
    |
    |void good_strlen_size_after_init(const char *s)
    |{
    |    size_t data = 0;
    |    data = strlen(s);
    |    char *p = (char *)malloc(data * sizeof(char));
    |    if (p) free(p);
    |}
    |
    |static int badStaticCpp = 0;
    |static void cppSink(int *data)
    |{
    |    if (badStaticCpp)
    |    {
    |        delete[] data;
    |    }
    |}
    |void bad_cpp_static_flag(void)
    |{
    |    int *data = new int[100];
    |    delete[] data;
    |    badStaticCpp = 1;
    |    cppSink(data);
    |}
    |
    |void bad_new_overflowed_bytes(void)
    |{
    |    int data = -1;
    |    char inputBuffer[20] = "";
    |    if (fgets(inputBuffer, 20, stdin) != NULL) data = atoi(inputBuffer);
    |    size_t dataBytes = data * sizeof(int);
    |    int *intPointer = (int *)new char[dataBytes];
    |    for (size_t i = 0; i < (size_t)data; i++)
    |    {
    |        intPointer[i] = 0;
    |    }
    |    delete[] intPointer;
    |}
    |""".stripMargin,
        "r10alloc.cpp"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <stdio.h>
    |#include <string.h>
    |
    |/* the CWE-789 shape: attacker-controlled sizes with and without the cap */
    |void bad_malloc_from_input(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p = (char *)malloc(n);
    |    if (p) free(p);
    |}
    |
    |void bad_alloca_from_input(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p = (char *)alloca(n);
    |    if (p) p[0] = 0;
    |}
    |
    |void good_capped(const char *userInput)
    |{
    |    size_t n = (size_t)atol(userInput);
    |    char *p;
    |    if (n == 0 || n > 4096) return;
    |    p = (char *)malloc(n);
    |    if (p) free(p);
    |}
    |
    |void good_constant_size(void)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p) free(p);
    |}
    |""".stripMargin,
        "uncontrolled.c"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |
    |/* the CWE-680 shape: an allocation sized by unguarded caller arithmetic */
    |int *bad_mul_overflow(unsigned int count)
    |{
    |    int *arr = (int *)malloc(count * sizeof(int));
    |    if (arr == NULL) return NULL;
    |    free(arr);
    |    return NULL;
    |}
    |""".stripMargin,
        "sizeoverflow.c"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |typedef struct hdr { size_t size; } hdr_t;
    |
    |#define PREFIX_SIZE (sizeof(size_t))
    |
    |/* An allocator that hands its block out past a size header, and the releases
    |   that move back onto the header before freeing. Each release below is the
    |   pair's own contract: the block starts one header before the pointer the
    |   caller holds, so moving back is the only way to free it. */
    |static void *hdr_malloc(size_t n)
    |{
    |    hdr_t *h = (hdr_t *)malloc(sizeof(hdr_t) + n);
    |    if (h == NULL) return NULL;
    |    h->size = n;
    |    return (void *)(h + 1);
    |}
    |
    |/* free((hdr_t *)p - 1): the move back onto the header sits in the call */
    |void good_free_inline_header(void *p)
    |{
    |    if (p == NULL) return;
    |    free((hdr_t *)p - 1);
    |}
    |
    |/* free((char *)ptr - PREFIX_SIZE): a macro names the offset */
    |void good_free_macro_prefix(void *ptr)
    |{
    |    if (ptr == NULL) return;
    |    free((char *)ptr - PREFIX_SIZE);
    |}
    |
    |/* p--; free(p): the pointer steps back onto the header, then releases */
    |void good_free_after_decrement(void *pPrior)
    |{
    |    hdr_t *p = (hdr_t *)pPrior;
    |    if (p == NULL) return;
    |    p--;
    |    free(p);
    |}
    |
    |/* p -= 1; free(p) */
    |void good_free_after_subtract_assign(void *p)
    |{
    |    hdr_t *h = (hdr_t *)p;
    |    if (h == NULL) return;
    |    h -= 1;
    |    free(h);
    |}
    |
    |/* a local copy of the parameter, moved back inside the release call */
    |void good_free_copy_inline_offset(void *p)
    |{
    |    if (p == NULL) return;
    |    void *copy = p;
    |    free((hdr_t *)copy - 1);
    |}
    |
    |/* a local copy of the parameter, stepped back then released */
    |void good_free_copy_after_decrement(void *p)
    |{
    |    if (p == NULL) return;
    |    hdr_t *copy = (hdr_t *)p;
    |    copy--;
    |    free(copy);
    |}
    |
    |/* a local copy of the parameter, subtracted then released */
    |void good_free_copy_after_subtract_assign(void *p)
    |{
    |    if (p == NULL) return;
    |    hdr_t *copy = (hdr_t *)p;
    |    copy -= 1;
    |    free(copy);
    |}
    |
    |/* the pair end to end */
    |void good_prefix_pair(size_t n)
    |{
    |    char *s = (char *)hdr_malloc(n);
    |    if (s == NULL) return;
    |    memset(s, 0, n);
    |    good_free_inline_header(s);
    |}
    |
    |/* the pair in a loop */
    |void good_prefix_pair_loop(size_t n, unsigned long count)
    |{
    |    unsigned long i;
    |    for (i = 0; i < count; i++)
    |    {
    |        char *s = (char *)hdr_malloc(n);
    |        if (s == NULL) return;
    |        memset(s, 0, n);
    |        good_free_macro_prefix(s);
    |    }
    |}
    |
    |/* the pair on a goto error path */
    |int good_prefix_pair_goto_error_path(size_t n, int fail)
    |{
    |    char *a = (char *)hdr_malloc(n);
    |    char *b = (char *)hdr_malloc(n);
    |    int rc = 0;
    |    if (a == NULL || b == NULL)
    |    {
    |        if (a) good_free_after_decrement(a);
    |        if (b) good_free_after_subtract_assign(b);
    |        return -1;
    |    }
    |    memset(a, 0, n);
    |    memset(b, 0, n);
    |    b[0] = 1;
    |    if (fail)
    |    {
    |        rc = -1;
    |        goto out;
    |    }
    |    rc = (int)a[0];
    |out:
    |    good_free_after_decrement(a);
    |    good_free_after_subtract_assign(b);
    |    return rc;
    |}
    |
    |/* a static cache holding the last block, released through the prefixed free */
    |static char *prefixCache = NULL;
    |
    |void good_prefix_static_cache(size_t n)
    |{
    |    char *s = (char *)hdr_malloc(n);
    |    if (s == NULL) return;
    |    memset(s, 0, n);
    |    if (prefixCache != NULL) good_free_inline_header(prefixCache);
    |    prefixCache = s;
    |}
    |
    |/* the releases the rule still owns: each leaves the start of a block this
    |   frame allocated */
    |
    |/* arithmetic forward off a fresh allocation */
    |void bad_free_plus_one(size_t n)
    |{
    |    char *p = (char *)malloc(n);
    |    if (p == NULL) return;
    |    memset(p, 0, n);
    |    free(p + 1);
    |}
    |
    |/* a walk forward over an allocation, then the release */
    |void bad_free_after_walk_over_allocation(const char *userInput)
    |{
    |    char *p = (char *)malloc(64);
    |    if (p == NULL) return;
    |    strncpy(p, userInput, 63);
    |    p[63] = 0;
    |    while (*p)
    |        p++;
    |    free(p);
    |}
    |
    |/* advanced by one amount, moved back by a smaller one: still off the start */
    |void bad_free_back_after_larger_advance(size_t n)
    |{
    |    char *p = (char *)malloc(n);
    |    if (p == NULL) return;
    |    memset(p, 0, n);
    |    p = p + 4;
    |    free(p - 1);
    |}
    |""".stripMargin,
        "offsetfree.c"
      )
      .moreCode(
        """
    |#define _GNU_SOURCE 1
    |#include <arpa/inet.h>
    |#include <fcntl.h>
    |#include <netinet/in.h>
    |#include <stdio.h>
    |#include <string.h>
    |#include <sys/socket.h>
    |#include <unistd.h>
    |
    |/* accept4 is accept with a flags argument. glibc and musl declare it when
    |   _GNU_SOURCE is defined; this libc leaves it out, so the fixture states
    |   the prototype the way a portable caller would */
    |#if defined(__APPLE__)
    |int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    |#endif
    |
    |/* ---- the descriptor pairs: an int handle acquired and released ---- */
    |
    |void good_open_close(const char *path)
    |{
    |    int fd = open(path, O_RDONLY);
    |    if (fd < 0) return;
    |    (void)write(fd, "x", 1);
    |    close(fd);
    |}
    |
    |void good_socket_close(void)
    |{
    |    int s = socket(AF_INET, SOCK_STREAM, 0);
    |    if (s < 0) return;
    |    (void)write(s, "y", 1);
    |    close(s);
    |}
    |
    |/* the listening socket is the caller's; the accepted one is released here */
    |void good_accept_close(int listener)
    |{
    |    int conn = accept(listener, NULL, NULL);
    |    if (conn < 0) return;
    |    (void)write(conn, "y", 1);
    |    close(conn);
    |}
    |
    |void good_accept4_close(int listener)
    |{
    |    int conn = accept4(listener, NULL, NULL, 0);
    |    if (conn < 0) return;
    |    (void)write(conn, "y", 1);
    |    close(conn);
    |}
    |
    |void good_creat_close(const char *path)
    |{
    |    int fd = creat(path, 0644);
    |    if (fd < 0) return;
    |    (void)write(fd, "x", 1);
    |    close(fd);
    |}
    |
    |void good_dup_close(const char *path)
    |{
    |    int fd = open(path, O_RDONLY);
    |    int copy;
    |    if (fd < 0) return;
    |    copy = dup(fd);
    |    if (copy < 0)
    |    {
    |        close(fd);
    |        return;
    |    }
    |    (void)write(copy, "x", 1);
    |    close(copy);
    |    close(fd);
    |}
    |
    |void good_dup2_close(const char *path, int target)
    |{
    |    int fd = open(path, O_RDONLY);
    |    int copy;
    |    if (fd < 0) return;
    |    copy = dup2(fd, target);
    |    if (copy < 0)
    |    {
    |        close(fd);
    |        return;
    |    }
    |    close(copy);
    |    close(fd);
    |}
    |
    |void good_pipe_close(void)
    |{
    |    int fds[2];
    |    if (pipe(fds) < 0) return;
    |    (void)write(fds[1], "x", 1);
    |    close(fds[0]);
    |    close(fds[1]);
    |}
    |
    |/* a connection helper: the descriptor socket() created is released with
    |   close(), on the error path and after the work */
    |int good_connect_socket_close(unsigned short port)
    |{
    |    struct sockaddr_in addr;
    |    int s = socket(AF_INET, SOCK_STREAM, 0);
    |    if (s < 0) return -1;
    |    memset(&addr, 0, sizeof(addr));
    |    addr.sin_family = AF_INET;
    |    addr.sin_port = htons(port);
    |    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    |    if (connect(s, (const struct sockaddr *)&addr, sizeof(addr)) < 0)
    |    {
    |        close(s);
    |        return -1;
    |    }
    |    (void)write(s, "x", 1);
    |    close(s);
    |    return 0;
    |}
    |
    |/* ---- the stream pairs: a FILE * acquired and released ---- */
    |
    |void good_fopen_fclose(const char *path)
    |{
    |    FILE *f = fopen(path, "r");
    |    if (f == NULL) return;
    |    (void)fgetc(f);
    |    fclose(f);
    |}
    |
    |/* the descriptor is the caller's; fdopen takes it over and fclose closes it */
    |void good_fdopen_fclose(int fd)
    |{
    |    FILE *f = fdopen(fd, "r");
    |    if (f == NULL) return;
    |    (void)fgetc(f);
    |    fclose(f);
    |}
    |
    |void good_tmpfile_fclose(void)
    |{
    |    FILE *f = tmpfile();
    |    if (f == NULL) return;
    |    (void)fgetc(f);
    |    fclose(f);
    |}
    |
    |/* ---- the mismatches: a stream released as a descriptor, and the reverse ---- */
    |
    |void bad_close_on_stream(const char *path)
    |{
    |    FILE *f = fopen(path, "r");
    |    if (f == NULL) return;
    |    (void)fgetc(f);
    |    close(f);
    |}
    |
    |void bad_fclose_on_descriptor(const char *path)
    |{
    |    int fd = open(path, O_RDONLY);
    |    if (fd < 0) return;
    |    (void)write(fd, "x", 1);
    |    fclose(fd);
    |}
    |""".stripMargin,
        "descriptors.c"
      )
      .moreCode(
        """
    |#include <stdio.h>
    |#include <winsock2.h>
    |
    |/* the Winsock release of a descriptor: closesocket is this platform's close.
    |   INVALID_SOCKET is (SOCKET)-1, spelled as the literal so the check reads as
    |   the failure sentinel it compares against */
    |void good_socket_closesocket(void)
    |{
    |    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    |    if (s == -1) return;
    |    (void)send(s, "x", 1, 0);
    |    closesocket(s);
    |}
    |
    |/* a stream released with the socket release */
    |void bad_closesocket_on_stream(const char *path)
    |{
    |    FILE *f = fopen(path, "r");
    |    if (f == NULL) return;
    |    (void)fgetc(f);
    |    closesocket(f);
    |}
    |""".stripMargin,
        "winsock.c"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <sys/mman.h>
    |
    |typedef struct hdr { size_t size; } hdr_t;
    |
    |#define SHORT_PREFIX 4
    |
    |/* An allocator that hands its block out past one size header: every non-NULL
    |   return is a malloc block advanced by sizeof(hdr_t) bytes. */
    |void *my_xalloc(size_t n)
    |{
    |    hdr_t *h = (hdr_t *)malloc(sizeof(hdr_t) + n);
    |    if (h == NULL)
    |        return NULL;
    |    h->size = n;
    |    return (void *)(h + 1);
    |}
    |
    |/* The same contract released with the byte spelling: (char *)p - sizeof(hdr_t)
    |   moves back the bytes (h + 1) moved forward. */
    |void bytes_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - sizeof(hdr_t));
    |}
    |
    |/* The family's own free: the move back onto the header sits in the call. */
    |void hdr_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((hdr_t *)p - 1);
    |}
    |
    |/* A second family: the same shape advancing by a fixed count of bytes. */
    |void *wide_xalloc(size_t n)
    |{
    |    char *p = (char *)malloc(32 + n);
    |    if (p == NULL)
    |        return NULL;
    |    return p + 32;
    |}
    |
    |void wide_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - 32);
    |}
    |
    |/* A third underlying family: the block comes from mmap, not malloc. */
    |void *map_xalloc(size_t n)
    |{
    |    struct hdr *h = (struct hdr *)mmap(NULL, sizeof(struct hdr) + n,
    |                                       PROT_READ | PROT_WRITE,
    |                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    |    if (h == MAP_FAILED)
    |        return NULL;
    |    h->size = n;
    |    return h + 1;
    |}
    |
    |void map_xfree(void *p)
    |{
    |    struct hdr *h;
    |    if (p == NULL)
    |        return;
    |    h = (struct hdr *)p - 1;
    |    (void)munmap(h, h->size);
    |}
    |
    |/* Moves back by an amount no allocator here advances: a family of its own. */
    |void short_xfree(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - SHORT_PREFIX);
    |}
    |
    |/* A plain wrapper: the allocation handed out unchanged keeps its family. */
    |void *xmalloc(size_t n)
    |{
    |    return malloc(n);
    |}
    |
    |/* The matched pair end to end: the free's name is not the allocator's. */
    |void good_offset_pair(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    hdr_xfree(s);
    |}
    |
    |/* The same release through the byte spelling of the move back. */
    |void good_offset_pair_other_spelling(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    bytes_xfree(s);
    |}
    |
    |/* The matched pair in a loop. */
    |void good_offset_pair_loop(size_t n, unsigned long count)
    |{
    |    unsigned long i;
    |    for (i = 0; i < count; i++)
    |    {
    |        char *s = (char *)my_xalloc(n);
    |        if (s == NULL)
    |            return;
    |        memset(s, 0, n);
    |        hdr_xfree(s);
    |    }
    |}
    |
    |/* The matched pair across a goto error path. */
    |int good_offset_pair_goto(size_t n, int fail)
    |{
    |    char *a = (char *)my_xalloc(n);
    |    char *b;
    |    int rc = 0;
    |    if (a == NULL)
    |        return -1;
    |    b = (char *)my_xalloc(n);
    |    if (b == NULL)
    |    {
    |        hdr_xfree(a);
    |        return -1;
    |    }
    |    memset(a, 0, n);
    |    memset(b, 0, n);
    |    b[0] = 1;
    |    if (fail)
    |    {
    |        rc = -1;
    |        goto out;
    |    }
    |    rc = (int)a[0];
    |out:
    |    hdr_xfree(a);
    |    hdr_xfree(b);
    |    return rc;
    |}
    |
    |/* A static cache holds the block between calls: the first caller
    |   allocates through the family, later callers reuse what it keeps. */
    |char *good_offset_static_cache(size_t n)
    |{
    |    static char *kept = NULL;
    |    if (kept != NULL)
    |        return kept;
    |    kept = (char *)my_xalloc(n);
    |    if (kept == NULL)
    |        return NULL;
    |    return kept;
    |}
    |
    |/* Two families of different amounts, each released by its own free. */
    |void good_two_amounts(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    char *w;
    |    if (s == NULL)
    |        return;
    |    w = (char *)wide_xalloc(n);
    |    if (w == NULL)
    |    {
    |        hdr_xfree(s);
    |        return;
    |    }
    |    memset(s, 0, n);
    |    memset(w, 0, n);
    |    wide_xfree(w);
    |    hdr_xfree(s);
    |}
    |
    |/* The mmap-backed family released by its own free. */
    |void good_map_pair(size_t n)
    |{
    |    char *s = (char *)map_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    map_xfree(s);
    |}
    |
    |/* A plain wrapper's allocation released with free. */
    |void good_plain_pair(size_t n)
    |{
    |    char *p = (char *)xmalloc(n);
    |    if (p == NULL)
    |        return;
    |    memset(p, 0, n);
    |    free(p);
    |}
    |
    |/* free() on an offset allocation: the block starts one header earlier. */
    |void bad_offset_freed_plain(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    free(s);
    |}
    |
    |/* The offset free on a plain allocation: the move back leaves the block. */
    |void bad_plain_freed_offset(size_t n)
    |{
    |    char *p = (char *)malloc(n);
    |    if (p == NULL)
    |        return;
    |    memset(p, 0, n);
    |    hdr_xfree(p);
    |}
    |
    |/* The offset free moved back by a different amount than the allocator
    |   advanced: no pairing, the families differ. */
    |void bad_offset_wrong_amount(size_t n)
    |{
    |    char *s = (char *)my_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    short_xfree(s);
    |}
    |
    |/* The statement-form pair: the allocator hands its block out past the
    |   header by stepping the returned pointer (p++) and the free steps it
    |   back (p--). Both moves normalise to the header's bytes, so the pair
    |   is one family. */
    |static void *sqlite_mem_malloc(int nByte)
    |{
    |    hdr_t *p = (hdr_t *)malloc(sizeof(hdr_t) + nByte);
    |    if (p == NULL)
    |        return NULL;
    |    p->size = nByte;
    |    p++;
    |    return (void *)p;
    |}
    |static void sqlite_mem_free(void *pPrior)
    |{
    |    hdr_t *p;
    |    if (pPrior == NULL)
    |        return;
    |    p = (hdr_t *)pPrior;
    |    p--;
    |    free(p);
    |}
    |void good_mem1_pair(int nByte)
    |{
    |    char *s = (char *)sqlite_mem_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    sqlite_mem_free(s);
    |}
    |void bad_mem1_freed_plain(int nByte)
    |{
    |    char *s = (char *)sqlite_mem_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    free(s);
    |}
    |
    |/* An allocator that advances a copy and returns the base: the returned
    |   identifier's own definitions decide, so it stays the plain heap. */
    |void *copy_advance_alloc(size_t n)
    |{
    |    char *base = (char *)malloc(n + 8);
    |    char *t;
    |    if (base == NULL)
    |        return NULL;
    |    t = base;
    |    t++;
    |    (void)t;
    |    return base;
    |}
    |void good_copy_base_pair(size_t n)
    |{
    |    char *b = (char *)copy_advance_alloc(n);
    |    if (b == NULL)
    |        return;
    |    memset(b, 0, n);
    |    free(b);
    |}
    |
    |/* The assignment-form pair: the allocator advances by rebinding the
    |   returned pointer (p = p + 8) and the free steps it back with a
    |   compound assign (p -= 8), both on a char pointer so the eight bytes
    |   are bytes on both sides. */
    |static void *sqlite_assign_malloc(int nByte)
    |{
    |    char *p = (char *)malloc(nByte + 8);
    |    if (p == NULL)
    |        return NULL;
    |    p[0] = 0;
    |    p = p + 8;
    |    return (void *)p;
    |}
    |static void sqlite_assign_free(void *pPrior)
    |{
    |    char *p;
    |    if (pPrior == NULL)
    |        return;
    |    p = (char *)pPrior;
    |    p -= 8;
    |    free(p);
    |}
    |void good_assign_mem_pair(int nByte)
    |{
    |    char *s = (char *)sqlite_assign_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    sqlite_assign_free(s);
    |}
    |void bad_assign_mem_freed_plain(int nByte)
    |{
    |    char *s = (char *)sqlite_assign_malloc(nByte);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, nByte);
    |    free(s);
    |}
    |
    |/* An allocator that advances a copy by assignment and returns the base:
    |   the returned identifier's own definitions decide, so it stays the
    |   plain heap. */
    |void *copy_assign_advance_alloc(size_t n)
    |{
    |    char *base = (char *)malloc(n + 8);
    |    char *t;
    |    if (base == NULL)
    |        return NULL;
    |    t = base + 8;
    |    (void)t;
    |    return base;
    |}
    |void good_copy_assign_base_pair(size_t n)
    |{
    |    char *b = (char *)copy_assign_advance_alloc(n);
    |    if (b == NULL)
    |        return;
    |    memset(b, 0, n);
    |    free(b);
    |}
    |
    |/* An allocator whose assignment advance steps back (in by sixteen, back
    |   by eight: the value stays inside the block): the advance refuses, the
    |   body concludes the plain heap, and no family mismatch can fire. */
    |void *back_assign_alloc(size_t n)
    |{
    |    char *p = (char *)malloc(n + 16);
    |    if (p == NULL)
    |        return NULL;
    |    p = p + 16;
    |    p = p - 8;
    |    return (void *)p;
    |}
    |void good_back_assign_pair(size_t n)
    |{
    |    char *p = (char *)back_assign_alloc(n);
    |    if (p == NULL)
    |        return;
    |    memset(p, 0, n);
    |    free(p);
    |}
    |/* A header struct with tail padding: sizeof counts the padding byte, so
    |   the struct spelling of the move back and the byte spelling must stay
    |   one amount and both pair with the allocator. */
    |typedef struct { char flag; size_t size; } padded_t;
    |void *padded_xalloc(size_t n)
    |{
    |    padded_t *h = (padded_t *)malloc(sizeof(padded_t) + n);
    |    if (h == NULL)
    |        return NULL;
    |    h->flag = 1;
    |    h->size = n;
    |    return (void *)(h + 1);
    |}
    |void padded_xfree_struct(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((padded_t *)p - 1);
    |}
    |void padded_xfree_bytes(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - sizeof(padded_t));
    |}
    |void good_padded_pair(size_t n)
    |{
    |    char *s = (char *)padded_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    padded_xfree_struct(s);
    |}
    |void good_padded_pair_bytes(size_t n)
    |{
    |    char *s = (char *)padded_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    padded_xfree_bytes(s);
    |}
    |
    |/* A wrapper returning the offset allocator's result unchanged keeps the
    |   family: its pair stays silent, free() on it is the mismatch. */
    |void *wrap_xalloc(size_t n)
    |{
    |    return my_xalloc(n);
    |}
    |void good_wrap_pair(size_t n)
    |{
    |    char *s = (char *)wrap_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    hdr_xfree(s);
    |}
    |void bad_wrap_freed_plain(size_t n)
    |{
    |    char *s = (char *)wrap_xalloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    free(s);
    |}
    |
    |/* A wrapper around mmap keeps the mmap family, and its pair stays silent. */
    |void *wrap_map_alloc(size_t n)
    |{
    |    return mmap(NULL, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    |}
    |void good_wrap_map_pair(size_t n)
    |{
    |    void *p = wrap_map_alloc(n);
    |    if (p == NULL)
    |        return;
    |    memset(p, 0, n);
    |    munmap(p, n);
    |}
    |
    |/* Every size a caller hands these functions is a constant, which is what
    |   makes the fixtures' sizes bounded. */
    |void drive_offset_families(void)
    |{
    |    good_offset_pair(32);
    |    good_offset_pair_other_spelling(32);
    |    good_offset_pair_loop(16, 3);
    |    good_offset_pair_goto(24, 1);
    |    good_offset_pair_goto(24, 0);
    |    good_offset_static_cache(20);
    |    good_two_amounts(28);
    |    good_map_pair(36);
    |    good_plain_pair(12);
    |    good_padded_pair(40);
    |    good_padded_pair_bytes(44);
    |    good_wrap_pair(48);
    |    bad_wrap_freed_plain(52);
    |    good_wrap_map_pair(56);
    |    bad_offset_freed_plain(32);
    |    bad_plain_freed_offset(32);
    |    bad_offset_wrong_amount(32);
    |    good_mem1_pair(48);
    |    bad_mem1_freed_plain(32);
    |    good_copy_base_pair(52);
    |    good_assign_mem_pair(56);
    |    bad_assign_mem_freed_plain(32);
    |    good_copy_assign_base_pair(60);
    |    good_back_assign_pair(64);
    |}
    |""".stripMargin,
        "offsetfamilies.c"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <string.h>
    |
    |typedef struct hdr { size_t size; } hdr_t;
    |
    |/* The malloc-based half of the same-named pair: the block comes from
    |   malloc, advanced by one header. */
    |static void *x_alloc(size_t n)
    |{
    |    hdr_t *h = (hdr_t *)malloc(sizeof(hdr_t) + n);
    |    if (h == NULL)
    |        return NULL;
    |    h->size = n;
    |    return (void *)(h + 1);
    |}
    |static void x_free(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((hdr_t *)p - 1);
    |}
    |void good_pair_a(size_t n)
    |{
    |    char *s = (char *)x_alloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    x_free(s);
    |}
    |
    |/* Every size a caller hands the pair functions is a constant, which is
    |   what makes the fixtures' sizes bounded. */
    |void drive_same_named_pairs(void)
    |{
    |    good_pair_a(32);
    |    good_pair_b(36);
    |    bad_cross_free_b(32);
    |}
    |""".stripMargin,
        "offsetpair_a.c"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |#include <string.h>
    |#include <sys/mman.h>
    |
    |typedef struct hdr { size_t size; } hdr_t;
    |
    |/* The mmap-based half of the same-named pair: the same amount advanced,
    |   but the block comes from mmap. Releasing it with a free that moves back
    |   onto a malloc block is the mismatch. */
    |static void *x_alloc(size_t n)
    |{
    |    struct hdr *h = (struct hdr *)mmap(NULL, sizeof(struct hdr) + n,
    |                                       PROT_READ | PROT_WRITE,
    |                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    |    if (h == MAP_FAILED)
    |        return NULL;
    |    h->size = n;
    |    return h + 1;
    |}
    |static void x_free(void *p)
    |{
    |    struct hdr *h;
    |    if (p == NULL)
    |        return;
    |    h = (struct hdr *)p - 1;
    |    (void)munmap(h, h->size);
    |}
    |/* a free of the malloc-based contract: it pairs with the other file's
    |   allocator, never with this file's */
    |static void z_free(void *p)
    |{
    |    if (p == NULL)
    |        return;
    |    free((char *)p - sizeof(struct hdr));
    |}
    |void good_pair_b(size_t n)
    |{
    |    char *s = (char *)x_alloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    x_free(s);
    |}
    |void bad_cross_free_b(size_t n)
    |{
    |    char *s = (char *)x_alloc(n);
    |    if (s == NULL)
    |        return;
    |    memset(s, 0, n);
    |    z_free(s);
    |}
    |""".stripMargin,
        "offsetpair_b.c"
      )
      .moreCode(
        """
    |#include <stdlib.h>
    |
    |/* The pool shapes: the block a bump allocator hands out belongs to the
    |   pool, the pool's destroy releases it, and no heap free does. */
    |typedef struct pool { char *base; size_t used; size_t cap; } pool_t;
    |
    |void *pool_alloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return NULL;
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |
    |void pool_destroy(pool_t *p)
    |{
    |    free(p->base);
    |    free(p);
    |}
    |
    |/* BUG CWE-590: a heap free of a block the pool owns */
    |void bad_free_of_pool_block(pool_t *p, size_t n)
    |{
    |    char *s = (char *)pool_alloc(p, n);
    |    if (s == NULL)
    |        return;
    |    s[0] = 1;
    |    free(s);
    |}
    |
    |/* BUG CWE-416: the use runs after the pool's destroy tore the block down */
    |int bad_use_after_pool_destroy(pool_t *p, size_t n)
    |{
    |    char *s = (char *)pool_alloc(p, n);
    |    if (s == NULL)
    |        return -1;
    |    s[0] = 1;
    |    pool_destroy(p);
    |    return s[0];
    |}
    |
    |/* the pair used correctly: the block lives between alloc and destroy, and
    |   nothing reads it afterwards */
    |int good_pool_pair(pool_t *p, size_t n)
    |{
    |    char *s = (char *)pool_alloc(p, n);
    |    if (s == NULL)
    |        return -1;
    |    s[0] = 1;
    |    pool_destroy(p);
    |    return 0;
    |}
    |
    |/* the block lives to function end: the pool owns it */
    |int good_pool_lives_to_end(pool_t *p, size_t n)
    |{
    |    char *s = (char *)pool_alloc(p, n);
    |    if (s == NULL)
    |        return -1;
    |    s[0] = 1;
    |    return 0;
    |}
    |
    |/* every pool of a list is destroyed with the block it handed out, in the
    |   loop */
    |int good_pool_loop(pool_t **pools, int count)
    |{
    |    int i;
    |    for (i = 0; i < count; i++) {
    |        pool_t *p = pools[i];
    |        char *s = (char *)pool_alloc(p, 16);
    |        if (s == NULL)
    |            continue;
    |        s[0] = 1;
    |        pool_destroy(p);
    |    }
    |    return 0;
    |}
    |
    |/* the error path destroys the pool and returns NULL, using nothing after */
    |char *good_pool_goto(pool_t *p, size_t n)
    |{
    |    char *s = (char *)pool_alloc(p, n);
    |    if (s == NULL)
    |        return NULL;
    |    if (n > p->cap) {
    |        pool_destroy(p);
    |        return NULL;
    |    }
    |    s[0] = 1;
    |    return s;
    |}
    |
    |/* the region-full fallback: the malloc arm is the caller's to release */
    |void *pool_alloc_or_malloc(pool_t *p, size_t n)
    |{
    |    if (p->cap - p->used < n)
    |        return malloc(n);
    |    void *r = p->base + p->used;
    |    p->used += n;
    |    return r;
    |}
    |
    |int good_pool_fallback(pool_t *p, size_t n)
    |{
    |    char *m;
    |    if (p->cap - p->used < n) {
    |        m = (char *)pool_alloc_or_malloc(p, n);
    |        if (m == NULL)
    |            return -1;
    |        m[0] = 1;
    |        free(m);
    |        return -1;
    |    }
    |    m = (char *)pool_alloc_or_malloc(p, n);
    |    if (m == NULL)
    |        return -1;
    |    m[0] = 1;
    |    return 0;
    |}
    |
    |/* a static holds a region pointer across calls: reuse, not a leak */
    |char *good_pool_static(pool_t *p, size_t n)
    |{
    |    static char *keep = NULL;
    |    if (keep == NULL)
    |        keep = (char *)pool_alloc(p, n);
    |    return keep;
    |}
    |
    |void drive_pools(void)
    |{
    |    static pool_t pool;
    |    static char storage[4096];
    |    static pool_t *list[2];
    |    pool.base = storage;
    |    pool.used = 0;
    |    pool.cap = sizeof(storage);
    |    list[0] = &pool;
    |    list[1] = &pool;
    |    bad_free_of_pool_block(&pool, 16);
    |    bad_use_after_pool_destroy(&pool, 16);
    |    good_pool_pair(&pool, 16);
    |    good_pool_lives_to_end(&pool, 16);
    |    good_pool_loop(list, 2);
    |    good_pool_fallback(&pool, 16);
    |    good_pool_static(&pool, 16);
    |}
    |""".stripMargin,
        "regions.c"
      )

  // the production order: the semantics pass runs first and the API pass reads its conclusions,
  // so a call resolved to one body is judged by that body's own conclusion
  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  // The declared region vocabulary, the way a project's in-house config names its pools and
  // contexts: the pool argument of the allocator, the global a context-less allocator reads,
  // and the lifecycle roles.
  private val regionConfig =
      """{"version": 1, "apis": [
        |  {"name": "palloc", "len": 1, "alloc": "pgmem",
        |   "region": {"role": "allocate", "context": "CurrentMemoryContext"}},
        |  {"name": "pfree", "free": "pgmem"},
        |  {"name": "apr_palloc", "len": 2, "alloc": "aprpool",
        |   "region": {"role": "allocate", "arg": 1}},
        |  {"name": "apr_pool_create", "region": {"role": "create", "arg": 1}},
        |  {"name": "apr_pool_clear", "region": {"role": "reset", "arg": 1}},
        |  {"name": "apr_pool_destroy", "region": {"role": "destroy", "arg": 1}},
        |  {"name": "MemoryContextDelete", "region": {"role": "destroy", "arg": 1}}
        |]}""".stripMargin

  private val declaredRegionCpg = code(
    """
    |#include <stdlib.h>
    |
    |void *palloc(unsigned long size);
    |void pfree(void *p);
    |extern void *CurrentMemoryContext;
    |void MemoryContextDelete(void *ctx);
    |typedef struct apr_pool_t apr_pool_t;
    |void *apr_palloc(apr_pool_t *pool, unsigned long size);
    |void apr_pool_create(apr_pool_t **pool, apr_pool_t *parent);
    |void apr_pool_clear(apr_pool_t *pool);
    |void apr_pool_destroy(apr_pool_t *pool);
    |
    |/* the matched pair: palloc's memory released by pfree */
    |int good_palloc_pfree(void)
    |{
    |    char *b = (char *)palloc(16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    pfree(b);
    |    return 0;
    |}
    |
    |/* BUG CWE-762: pfree releases palloc's family, not the heap's */
    |void bad_pfree_of_malloc(void)
    |{
    |    char *b = (char *)malloc(16);
    |    if (b == NULL)
    |        return;
    |    b[0] = 1;
    |    pfree(b);
    |}
    |
    |/* BUG CWE-762: a heap free of the pool's block */
    |void bad_free_of_pooled_block(apr_pool_t *pool)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return;
    |    b[0] = 1;
    |    free(b);
    |}
    |
    |/* BUG CWE-416, high: the use runs after the context's delete */
    |int bad_use_after_context_delete(void)
    |{
    |    char *b = (char *)palloc(16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    MemoryContextDelete(CurrentMemoryContext);
    |    return b[0];
    |}
    |
    |/* BUG CWE-416, high: the use runs after the pool's destroy */
    |int bad_use_after_pool_destroy_declared(apr_pool_t *pool)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    apr_pool_destroy(pool);
    |    return b[0];
    |}
    |
    |/* BUG CWE-416, medium: after the clear the block is only maybe gone */
    |int bad_use_after_pool_clear(apr_pool_t *pool)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    apr_pool_clear(pool);
    |    return b[0];
    |}
    |
    |/* the created pool owns its block; the out-pointer create and the destroy pair */
    |int good_created_pool(void)
    |{
    |    apr_pool_t *pool = NULL;
    |    char *b;
    |    apr_pool_create(&pool, NULL);
    |    if (pool == NULL)
    |        return -1;
    |    b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    apr_pool_destroy(pool);
    |    return 0;
    |}
    |
    |/* the block lives to function end with its pool */
    |int good_palloc_lives_to_end(apr_pool_t *pool)
    |{
    |    char *b = (char *)apr_palloc(pool, 16);
    |    if (b == NULL)
    |        return -1;
    |    b[0] = 1;
    |    return 0;
    |}
    |""".stripMargin,
    "regions_declared.c"
  )
  new MemorySemanticsPass(declaredRegionCpg, Some(regionConfig)).createAndApply()
  new MemoryApiPass(declaredRegionCpg, Some(regionConfig)).createAndApply()
  new ExtentPass(declaredRegionCpg).createAndApply()
  new GuardPass(declaredRegionCpg).createAndApply()
  new ValueOriginPass(declaredRegionCpg).createAndApply()
  new AllocationStatePass(declaredRegionCpg).createAndApply()
  new MemorySafetyFindingPass(declaredRegionCpg, Some(regionConfig)).createAndApply()

  private def findingsIn(method: String): Set[String] =
      cpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  private def declaredFindingsIn(method: String): Set[String] =
      declaredRegionCpg.method
          .name(method)
          .ast
          .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          .filter(_.tag.name("ms-finding").l.nonEmpty)
          .flatMap(_.tag.name("ms-finding").value.l)
          .l
          .toSet

  "MS-ALLOC-005/006/007 (wrong deallocation)" should:
    "fire on a free of pointer arithmetic over the allocation (CWE-761)" in {
        findingsIn("bad_free_offset") should contain("MS-ALLOC-006")
    }
    "report a walked-then-freed pointer at the walk's increment, where the suite marks it" in {
        val walks = cpg.method.name("bad_walk_then_free").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-006"))
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Call].l
        walks.map(_.code) shouldBe List("data++")
    }
    "report both releases of a double free (CWE-415)" in {
        val sites = cpg.method.name("bad_double_free").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.AstNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-001")).l
        sites.flatMap(_.lineNumber).map(_.toInt).distinct.size shouldBe 2
        findingsIn("good_free_once") should not contain "MS-ALLOC-001"
        def siteLines(m: String) = cpg.method.name(m).ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.AstNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-001"))
            .flatMap(_.lineNumber).map(_.toInt).l.distinct
        siteLines("bad_double_free_through_copy").size shouldBe 2
        val firstFree = cpg.method.name("bad_rebound_then_released").call.nameExact("free")
            .flatMap(_.lineNumber).map(_.toInt).l.min
        siteLines("bad_rebound_then_released") should not be empty
        siteLines("bad_rebound_then_released") should not contain firstFree
        findingsIn("good_free_elements_then_container") should not contain "MS-ALLOC-001"
    }
    "report a release a file-static flag a caller set decides (CWE-415 across a call)" in {
        findingsIn("bad_static_flag_sink") should contain("MS-ALLOC-001")
        findingsIn("good_static_flag_other_pointer") should not contain "MS-ALLOC-001"
    }
    "report the callee's own release as a site of the same double free" in {
        findingsIn("bad_cpp_static_flag") should contain("MS-ALLOC-001")
        val sites = cpg.method.name("cppSink").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-001")).l
        sites should not be empty
    }
    "report a pointer a callee returns after releasing it, freed again by the caller" in {
        findingsIn("bad_source_returns_released") should contain("MS-ALLOC-001")
        findingsIn("good_source_returns_live") should not contain "MS-ALLOC-001"
    }
    "report a release through a local function pointer" in {
        findingsIn("bad_pointer_sink") should contain("MS-ALLOC-001")
    }
    "stay silent when the walk is over a copy and the original is freed" in {
        findingsIn("good_walk_a_copy") should not contain "MS-ALLOC-006"
    }
    "stay silent when the walk is over a pointer no allocation in this frame produced" in {
        findingsIn("silent_walk_then_free") should not contain "MS-ALLOC-006"
    }
    "stay silent when the release moves back onto a size header in the free call" in {
        findingsIn("good_free_inline_header") should not contain "MS-ALLOC-006"
    }
    "stay silent when a macro names the offset the release moves back" in {
        findingsIn("good_free_macro_prefix") should not contain "MS-ALLOC-006"
    }
    "stay silent when the pointer steps back onto the header before the release" in {
        findingsIn("good_free_after_decrement") should not contain "MS-ALLOC-006"
        findingsIn("good_free_after_subtract_assign") should not contain "MS-ALLOC-006"
    }
    "stay silent when the release moves a local copy of the parameter back" in {
        findingsIn("good_free_copy_inline_offset") should not contain "MS-ALLOC-006"
        findingsIn("good_free_copy_after_decrement") should not contain "MS-ALLOC-006"
        findingsIn("good_free_copy_after_subtract_assign") should not contain "MS-ALLOC-006"
    }
    "stay silent on the prefixed pair, in a loop, on a goto error path and over a static cache" in {
        findingsIn("good_prefix_pair") should not contain "MS-ALLOC-006"
        findingsIn("good_prefix_pair_loop") should not contain "MS-ALLOC-006"
        findingsIn("good_prefix_pair_goto_error_path") should not contain "MS-ALLOC-006"
        findingsIn("good_prefix_static_cache") should not contain "MS-ALLOC-006"
    }
    "keep reporting arithmetic forward off a fresh allocation" in {
        findingsIn("bad_free_plus_one") should contain("MS-ALLOC-006")
    }
    "keep reporting a release after a forward walk over an allocation" in {
        val walks = cpg.method.name("bad_free_after_walk_over_allocation").ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-006"))
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.Call].l
        walks.map(_.code) shouldBe List("p++")
    }
    "keep reporting a move back from an allocation advanced by a larger amount" in {
        findingsIn("bad_free_back_after_larger_advance") should contain("MS-ALLOC-006")
    }
    "stay silent when the arithmetic result is not what is freed" in {
        findingsIn("good_free_original") should not contain "MS-ALLOC-006"
    }
    "fire on a free of a static local (CWE-590)" in {
        findingsIn("bad_free_static") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a string literal (CWE-590)" in {
        findingsIn("bad_free_string_literal") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a stack array (CWE-590)" in {
        findingsIn("bad_free_stack") shouldBe Set("MS-ALLOC-005")
    }
    "fire on a free of a local's address (CWE-590 through the state fact)" in {
        findingsIn("bad_free_address_of_local") should contain("MS-ALLOC-005")
    }
    "stay silent on an ordinary heap free" in {
        findingsIn("good_free_heap") shouldBe empty
    }
    "fire on malloc released with delete (CWE-762)" in {
        findingsIn("bad_mismatched_malloc_delete") should contain("MS-ALLOC-007")
    }
    "fire on new released with free (CWE-762)" in {
        findingsIn("bad_mismatched_new_free") should contain("MS-ALLOC-007")
    }
    "stay silent on a matched new/delete pair" in {
        findingsIn("good_matched_new_delete") should not contain "MS-ALLOC-007"
    }
    "fire on new[] released with a scalar delete, and new with delete[] (CWE-762)" in {
        findingsIn("bad_array_new_scalar_delete") should contain("MS-ALLOC-007")
        findingsIn("bad_scalar_new_array_delete") should contain("MS-ALLOC-007")
    }
    "stay silent on a matched new[]/delete[] pair" in {
        findingsIn("good_matched_array_new_delete") should not contain "MS-ALLOC-007"
    }

  "descriptor pairs" should:

    "stay silent on an open descriptor released with close" in {
        findingsIn("good_open_close") shouldBe empty
    }
    "stay silent on a socket released with close" in {
        findingsIn("good_socket_close") shouldBe empty
    }
    "stay silent on an accepted socket released with close" in {
        findingsIn("good_accept_close") shouldBe empty
    }
    "stay silent on a descriptor from accept4 released with close" in {
        findingsIn("good_accept4_close") shouldBe empty
    }
    "stay silent on a descriptor from creat released with close" in {
        findingsIn("good_creat_close") shouldBe empty
    }
    "stay silent on a duplicated descriptor released with close" in {
        findingsIn("good_dup_close") shouldBe empty
        findingsIn("good_dup2_close") shouldBe empty
    }
    "stay silent on both ends of a pipe released with close" in {
        findingsIn("good_pipe_close") shouldBe empty
    }
    "stay silent on a connection helper's socket released with close" in {
        findingsIn("good_connect_socket_close") shouldBe empty
    }
    "stay silent on a stream fopen returned, released with fclose" in {
        findingsIn("good_fopen_fclose") shouldBe empty
    }
    "stay silent on a stream fdopen took over from a descriptor, released with fclose" in {
        findingsIn("good_fdopen_fclose") shouldBe empty
    }
    "stay silent on a temporary stream tmpfile returned, released with fclose" in {
        findingsIn("good_tmpfile_fclose") shouldBe empty
    }
    "stay silent on a Winsock socket released with closesocket" in {
        findingsIn("good_socket_closesocket") shouldBe empty
    }
    "fire on close of a stream fopen returned" in {
        findingsIn("bad_close_on_stream") shouldBe Set("MS-ALLOC-007")
    }
    "fire on fclose of a descriptor open returned" in {
        findingsIn("bad_fclose_on_descriptor") shouldBe Set("MS-ALLOC-007")
    }
    "fire on closesocket of a stream fopen returned" in {
        findingsIn("bad_closesocket_on_stream") shouldBe Set("MS-ALLOC-007")
    }

  "offset allocator families (MS-ALLOC-007)" should:
    "fire on free of an offset allocation" in {
        findingsIn("bad_offset_freed_plain") shouldBe Set("MS-ALLOC-007")
    }
    "fire on the offset free of a plain allocation" in {
        findingsIn("bad_plain_freed_offset") shouldBe Set("MS-ALLOC-007")
    }
    "fire on the offset free of a different amount than the allocator advanced" in {
        findingsIn("bad_offset_wrong_amount") shouldBe Set("MS-ALLOC-007")
    }
    "stay silent on the matched pair, its other spelling, in a loop, over a goto error path and a static cache" in {
        findingsIn("good_offset_pair") shouldBe empty
        findingsIn("good_offset_pair_other_spelling") shouldBe empty
        findingsIn("good_offset_pair_loop") shouldBe empty
        findingsIn("good_offset_pair_goto") shouldBe empty
        findingsIn("good_offset_static_cache") shouldBe empty
    }
    "stay silent when two families of different amounts each free their own" in {
        findingsIn("good_two_amounts") shouldBe empty
    }
    "stay silent on a different underlying family's own pair" in {
        findingsIn("good_map_pair") shouldBe empty
    }
    "stay silent on a plain wrapper freed with free" in {
        findingsIn("good_plain_pair") shouldBe empty
    }
    "stay silent on a padded header's pair in the struct spelling and the byte spelling" in {
        findingsIn("good_padded_pair") shouldBe empty
        findingsIn("good_padded_pair_bytes") shouldBe empty
    }
    "stay silent on the statement-form pair, whose allocator steps p++ and whose free steps p--" in {
        findingsIn("good_mem1_pair") shouldBe empty
    }
    "fire on free of the statement-form allocator's result" in {
        findingsIn("bad_mem1_freed_plain") shouldBe Set("MS-ALLOC-007")
    }
    "stay silent on an allocator that advances a copy and returns the base" in {
        findingsIn("good_copy_base_pair") shouldBe empty
    }
    "stay silent on the assignment-form pair, whose allocator rebinds p and whose free steps p back" in {
        findingsIn("good_assign_mem_pair") shouldBe empty
    }
    "fire on free of the assignment-form allocator's result" in {
        findingsIn("bad_assign_mem_freed_plain") shouldBe Set("MS-ALLOC-007")
    }
    "stay silent on an allocator that advances a copy by assignment and returns the base" in {
        findingsIn("good_copy_assign_base_pair") shouldBe empty
    }
    "keep an allocator whose assignment advance steps back plain: no family mismatch" in {
        // the offset family refuses, so the release cannot be a cross-family
        // one; the arithmetic the body kept is the offset-free rule's own
        // question and stays reported
        findingsIn("good_back_assign_pair") should not contain "MS-ALLOC-007"
        findingsIn("good_back_assign_pair") should not contain "MS-ALLOC-003"
    }
    "keep a wrapper of the offset allocator in the family: its pair silent, free() the mismatch" in {
        findingsIn("good_wrap_pair") shouldBe empty
        findingsIn("bad_wrap_freed_plain") shouldBe Set("MS-ALLOC-007")
    }
    "stay silent on a wrapper around mmap released with munmap" in {
        findingsIn("good_wrap_map_pair") shouldBe empty
    }

  "same-named allocators of different underlying families (own-channel keys)" should:
    "stay silent on each file's own pair" in {
        findingsIn("good_pair_a") shouldBe empty
        findingsIn("good_pair_b") shouldBe empty
    }
    "not cross-pair: the other underlying family's free on one file's result reports" in {
        findingsIn("bad_cross_free_b") shouldBe Set("MS-ALLOC-007")
    }

  "MS-ALLOC-008/009 (uncontrolled size)" should:
    "fire on a new[] count with only a lower bound (CWE-789)" in {
        findingsIn("bad_new_count_lower_bound") should contain("MS-ALLOC-008")
    }
    "stay silent on a new[] count capped above" in {
        findingsIn("good_new_count_capped") should not contain "MS-ALLOC-008"
    }
    "fire on a scanf-filled size whose initialiser is a constant" in {
        findingsIn("bad_scanf_size_after_init") should contain("MS-ALLOC-008")
    }
    "stay silent on a strlen-derived size with a constant initialiser" in {
        findingsIn("good_strlen_size_after_init") should not contain "MS-ALLOC-008"
    }
    "fire on the write over a new[] sized by overflowed arithmetic (CWE-680)" in {
        findingsIn("bad_new_overflowed_bytes") should contain("MS-BOUND-007")
    }
    "fire on an attacker-controlled malloc size (CWE-789)" in {
        findingsIn("bad_malloc_from_input") shouldBe Set("MS-ALLOC-008")
    }
    "fire on an attacker-controlled alloca size (CWE-789, stack)" in {
        findingsIn("bad_alloca_from_input") shouldBe Set("MS-ALLOC-008")
    }
    "stay silent when the size is capped above" in {
        findingsIn("good_capped") shouldBe empty
    }
    "stay silent on a constant size" in {
        findingsIn("good_constant_size") shouldBe empty
    }
    "fire on an allocation sized by unguarded caller arithmetic (CWE-680)" in {
        findingsIn("bad_mul_overflow") should contain("MS-ALLOC-009")
    }

  "region pools (MS-ALLOC-005/002)" should:
    "fire on a heap free of a block the pool handed out (CWE-590)" in {
        findingsIn("bad_free_of_pool_block") shouldBe Set("MS-ALLOC-005")
    }
    "fire on the use after the pool's destroy tore the block down (CWE-416)" in {
        findingsIn("bad_use_after_pool_destroy") shouldBe Set("MS-ALLOC-002")
    }
    "stay silent on the pool pair used correctly" in {
        findingsIn("good_pool_pair") shouldBe empty
    }
    "stay silent on a region allocation that lives to function end" in {
        findingsIn("good_pool_lives_to_end") shouldBe empty
    }
    "stay silent when the loop's destroy releases each pool's own block" in {
        findingsIn("good_pool_loop") shouldBe empty
    }
    "stay silent on the goto error path that destroys the pool and uses nothing after" in {
        findingsIn("good_pool_goto") shouldBe empty
    }
    "stay silent when the caller frees only the fallback's malloc arm by hand" in {
        findingsIn("good_pool_fallback") shouldBe empty
    }
    "stay silent on a static holding a region pointer across calls" in {
        findingsIn("good_pool_static") shouldBe empty
    }

  "declared region roles (MS-ALLOC-007/002)" should:
    "stay silent on the matched palloc/pfree pair" in {
        declaredFindingsIn("good_palloc_pfree") shouldBe empty
    }
    "fire on pfree of malloc memory (CWE-762)" in {
        declaredFindingsIn("bad_pfree_of_malloc") shouldBe Set("MS-ALLOC-007")
    }
    "fire on a heap free of the pool's block (CWE-762)" in {
        declaredFindingsIn("bad_free_of_pooled_block") shouldBe Set("MS-ALLOC-007")
    }
    "fire on the use after the context's delete (CWE-416)" in {
        declaredFindingsIn("bad_use_after_context_delete") shouldBe Set("MS-ALLOC-002")
    }
    "fire on the use after the pool's destroy (CWE-416)" in {
        declaredFindingsIn("bad_use_after_pool_destroy_declared") shouldBe Set("MS-ALLOC-002")
    }
    "fire on the use after the pool's clear below the rule's own confidence (CWE-416)" in {
        val m = declaredRegionCpg.method.nameExact("bad_use_after_pool_clear").head
        val sites = m.ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
            .l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        sites should not be empty
        sites.flatMap(_.tag.name("ms-confidence").value.l) should contain(
          "MS-ALLOC-002=medium"
        )
    }
    "report the use after the pool's destroy at the rule's own confidence" in {
        val m = declaredRegionCpg.method.nameExact("bad_use_after_pool_destroy_declared").head
        val sites = m.ast
            .collectAll[io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
            .l
            .filter(_.tag.name("ms-finding").value.l.contains("MS-ALLOC-002"))
        sites should not be empty
        sites.flatMap(_.tag.name("ms-confidence").value.l) should not contain (
          "MS-ALLOC-002=medium"
        )
    }
    "stay silent on the created pool's pair and on a block that lives to function end" in {
        declaredFindingsIn("good_created_pool") shouldBe empty
        declaredFindingsIn("good_palloc_lives_to_end") shouldBe empty
    }
end WrongDeallocationRuleTests
