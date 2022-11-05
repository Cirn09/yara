
#include <assert.h>
#include <float.h>
#include <math.h>
#include <string.h>
#include <yara.h>
#include <yara/arena.h>
#include <yara/endian.h>
#include <yara/error.h>
#include <yara/exec.h>
#include <yara/globals.h>
#include <yara/limits.h>
#include <yara/mem.h>
#include <yara/modules.h>
#include <yara/object.h>
#include <yara/re.h>
#include <yara/sizedstr.h>
#include <yara/stopwatch.h>
#include <yara/strutils.h>
#include <yara/unaligned.h>
#include <yara/utils.h>

static const uint8_t* jmp_if_patched(int condition, const uint8_t* ip);

void code_dump(YR_SCAN_CONTEXT* context);