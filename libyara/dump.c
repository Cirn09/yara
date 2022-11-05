
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

#include <yara/dump.h>

#define MEM_SIZE YR_MAX_LOOP_NESTING*(YR_MAX_LOOP_VARS + YR_INTERNAL_LOOP_VARS)

#define p8(x)  printf("%02x ", (uint8_t) x)
#define p16(x) printf("%04x ", (uint16_t) x)
#define p32(x) printf("%08x ", (uint32_t) x)
#define p64(x) printf("%016llx ", (uint64_t) x)
#define f32(x) printf("%f ", (float) x)
#define f64(x) printf("%f ", (double) x)
#define ps(x)  printf("%s ", (char*) x)

static const uint8_t* jmp_if_patched(int condition, const uint8_t* ip)
{
  int32_t off = 0;
  off = yr_unaligned_u32(ip);
  p32(off);
  off = sizeof(int32_t);

  return ip + off;
}

void code_dump(YR_SCAN_CONTEXT* context)
{
  const uint8_t* ip = context->rules->code_start;

  YR_VALUE mem[MEM_SIZE];
  YR_VALUE args[YR_MAX_FUNCTION_ARGS];
  YR_VALUE r1;
  YR_VALUE r2;
  YR_VALUE r3;
  YR_VALUE r4;

  YR_VALUE_STACK stack;

  uint64_t elapsed_time;

#ifdef YR_PROFILING_ENABLED
  uint64_t start_time;
#endif

  uint32_t current_rule_idx = 0;
  YR_RULE* current_rule = NULL;
  YR_RULE* rule;
  YR_MATCH* match;
  YR_OBJECT_FUNCTION* function;
  YR_OBJECT** obj_ptr;
  YR_ARENA* obj_arena;
  YR_NOTEBOOK* it_notebook;

  char* identifier;
  char* args_fmt;

  int found;
  int count;
  int result = ERROR_SUCCESS;
  int cycle = 0;
  int obj_count = 0;

  bool stop = false;

  uint8_t opcode;

  puts("=================== START ===================");

  while (!stop)
  {
    // Read the opcode from the address indicated by the instruction pointer.
    opcode = *ip;

    // Advance the instruction pointer, which now points past the opcode.
    ip++;

    switch (opcode)
    {
    case OP_NOP:
      printf("NOP ");

      putchar('\n');
      break;

    case OP_HALT:
      printf("HALT ");

      putchar('\n');
      stop = true;
      break;

    case OP_ITER_START_ARRAY:
      printf("ITER_START_ARRAY ");

      putchar('\n');
      break;

    case OP_ITER_START_DICT:
      printf("ITER_START_DICT ");

      putchar('\n');
      break;

    case OP_ITER_START_INT_RANGE:
      printf("ITER_START_INT_RANGE ");

      putchar('\n');
      break;

    case OP_ITER_START_INT_ENUM:
      printf("ITER_START_INT_ENUM ");

      putchar('\n');
      break;

    case OP_ITER_START_STRING_SET:
      printf("ITER_START_STRING_SET ");

      putchar('\n');
      break;

    case OP_ITER_START_TEXT_STRING_SET:
      printf("ITER_START_TEXT_STRING_SET ");

      putchar('\n');
      break;

    case OP_ITER_NEXT:
      printf("ITER_NEXT ");

      putchar('\n');
      break;

    case OP_ITER_CONDITION:
      printf("ITER_CONDITION ");

      putchar('\n');
      break;

    case OP_ITER_END:
      printf("ITER_END ");

      putchar('\n');
      break;

    case OP_PUSH:
      printf("PUSH ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_PUSH_8:
      printf("PUSH_8 ");
      p8(*ip);

      putchar('\n');
      ip += sizeof(uint8_t);
      break;

    case OP_PUSH_16:
      printf("PUSH_16 ");
      p16(yr_unaligned_u16(ip));

      putchar('\n');
      ip += sizeof(uint16_t);
      break;

    case OP_PUSH_32:
      printf("PUSH_32 ");
      p32(yr_unaligned_u32(ip));

      putchar('\n');
      ip += sizeof(uint32_t);
      break;

    case OP_PUSH_U:
      printf("PUSH_U ");

      putchar('\n');
      break;

    case OP_POP:
      printf("POP ");

      putchar('\n');
      break;

    case OP_CLEAR_M:
      printf("CLEAR_M ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_ADD_M:
      printf("ADD_M ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_INCR_M:
      printf("INCR_M ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_PUSH_M:
      printf("PUSH_M ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_POP_M:
      printf("POP_M ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_SET_M:
      printf("SET_M ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_SWAPUNDEF:
      printf("SWAPUNDEF ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_JNUNDEF:
      printf("JNUNDEF ");

      ip = jmp_if_patched(!is_undef(r1), ip);
      putchar('\n');
      break;

    case OP_JUNDEF_P:
      printf("JUNDEF_P ");

      putchar('\n');
      ip = jmp_if_patched(is_undef(r1), ip);
      break;

    case OP_JL_P:
      printf("JL_P ");

      putchar('\n');
      ip = jmp_if_patched(r1.i < r2.i, ip);
      break;

    case OP_JLE_P:
      printf("JLE_P ");

      putchar('\n');
      ip = jmp_if_patched(r1.i <= r2.i, ip);
      break;

    case OP_JTRUE:
      printf("JTRUE ");

      putchar('\n');
      ip = jmp_if_patched(!is_undef(r1) && r1.i, ip);
      break;

    case OP_JTRUE_P:
      printf("JTRUE_P ");

      putchar('\n');
      ip = jmp_if_patched(!is_undef(r1) && r1.i, ip);
      break;

    case OP_JFALSE:
      printf("JFALSE ");

      putchar('\n');
      ip = jmp_if_patched(!is_undef(r1) && !r1.i, ip);
      break;

    case OP_JFALSE_P:
      printf("JFALSE_P ");

      putchar('\n');
      ip = jmp_if_patched(!is_undef(r1) && !r1.i, ip);
      break;

    case OP_JZ:
      printf("JZ ");

      putchar('\n');
      ip = jmp_if_patched(r1.i == 0, ip);
      break;

    case OP_JZ_P:
      printf("JZ_P ");

      putchar('\n');
      ip = jmp_if_patched(r1.i == 0, ip);
      break;

    case OP_AND:
      printf("AND ");

      putchar('\n');
      break;

    case OP_OR:
      printf("OR ");

      putchar('\n');
      break;

    case OP_NOT:
      printf("NOT ");

      putchar('\n');
      break;

    case OP_DEFINED:
      printf("DEFINED ");

      putchar('\n');
      break;

    case OP_MOD:
      printf("MOD ");

      putchar('\n');
      break;

    case OP_SHR:
      printf("SHR ");

      putchar('\n');
      break;

    case OP_SHL:
      printf("SHL ");

      putchar('\n');
      break;

    case OP_BITWISE_NOT:
      printf("BITWISE_NOT ");

      putchar('\n');
      break;

    case OP_BITWISE_AND:
      printf("BITWISE_AND ");

      putchar('\n');
      break;

    case OP_BITWISE_OR:
      printf("BITWISE_OR ");

      putchar('\n');
      break;

    case OP_BITWISE_XOR:
      printf("BITWISE_XOR ");

      putchar('\n');
      break;

    case OP_PUSH_RULE:
      printf("PUSH_RULE ");
      p64(yr_unaligned_u64(ip));
      ip += sizeof(uint64_t);
      break;

    case OP_INIT_RULE:
      printf("INIT_RULE ");

      putchar('\n');
      ip = jmp_if_patched(RULE_IS_DISABLED(current_rule), ip);
      break;

    case OP_MATCH_RULE:
      printf("MATCH_RULE ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_OBJ_LOAD:
      printf("OBJ_LOAD ");
      ps(yr_unaligned_char_ptr(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_OBJ_FIELD:
      printf("OBJ_FIELD ");
      ps(yr_unaligned_char_ptr(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_OBJ_VALUE:
      printf("OBJ_VALUE ");

      putchar('\n');
      break;

    case OP_INDEX_ARRAY:
      printf("INDEX_ARRAY ");

      putchar('\n');
      break;

    case OP_LOOKUP_DICT:
      printf("LOOKUP_DICT ");

      putchar('\n');
      break;

    case OP_CALL:
      printf("CALL ");
      ps(yr_unaligned_char_ptr(ip));

      putchar('\n');

      ip += sizeof(uint64_t);
      break;

    case OP_FOUND:
      printf("FOUND ");

      putchar('\n');
      break;

    case OP_FOUND_AT:
      printf("FOUND_AT ");

      putchar('\n');
      break;

    case OP_FOUND_IN:
      printf("FOUND_IN ");

      putchar('\n');
      break;

    case OP_COUNT:
      printf("COUNT ");

      putchar('\n');
      break;

    case OP_COUNT_IN:
      printf("COUNT_IN ");

      putchar('\n');
      break;

    case OP_OFFSET:
      printf("OFFSET ");

      putchar('\n');
      break;

    case OP_LENGTH:
      printf("LENGTH ");

      putchar('\n');
      break;

    case OP_OF:
    case OP_OF_PERCENT:
      printf("OF_PERCENT ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      printf("OF_PERCENT\n");
      ip += sizeof(uint64_t);
      break;

    case OP_OF_FOUND_IN:
      printf("OF_FOUND_IN ");

      putchar('\n');
      break;

    case OP_OF_FOUND_AT:
      printf("OF_FOUND_AT ");

      putchar('\n');
      break;

    case OP_FILESIZE:
      printf("FILESIZE ");

      putchar('\n');
      break;

    case OP_ENTRYPOINT:
      printf("ENTRYPOINT ");

      putchar('\n');
      break;

    case OP_INT8:
      printf("INT8 ");

      putchar('\n');
      break;

    case OP_INT16:
      printf("INT16 ");

      putchar('\n');
      break;

    case OP_INT32:
      printf("INT32 ");

      putchar('\n');
      break;

    case OP_UINT8:
      printf("UINT8 ");

      putchar('\n');
      break;

    case OP_UINT16:
      printf("UINT16 ");

      putchar('\n');
      break;

    case OP_UINT32:
      printf("UINT32 ");

      putchar('\n');
      break;

    case OP_INT8BE:
      printf("INT8BE ");

      putchar('\n');
      break;

    case OP_INT16BE:
      printf("INT16BE ");

      putchar('\n');
      break;

    case OP_INT32BE:
      printf("INT32BE ");

      putchar('\n');
      break;

    case OP_UINT8BE:
      printf("UINT8BE ");

      putchar('\n');
      break;

    case OP_UINT16BE:
      printf("UINT16BE ");

      putchar('\n');
      break;

    case OP_UINT32BE:
      printf("UINT32BE ");

      putchar('\n');
      break;

    case OP_IMPORT:
      printf("IMPORT ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);

      break;

    case OP_MATCHES:
      printf("MATCHES ");

      putchar('\n');
      break;

    case OP_INT_TO_DBL:
      printf("INT_TO_DBL ");
      p64(yr_unaligned_u64(ip));

      putchar('\n');
      ip += sizeof(uint64_t);
      break;

    case OP_STR_TO_BOOL:
      printf("STR_TO_BOOL ");

      putchar('\n');
      break;

    case OP_INT_EQ:
      printf("INT_EQ ");

      putchar('\n');
      break;

    case OP_INT_NEQ:
      printf("INT_NEQ ");

      putchar('\n');
      break;

    case OP_INT_LT:
      printf("INT_LT ");

      putchar('\n');
      break;

    case OP_INT_GT:
      printf("INT_GT ");

      putchar('\n');
      break;

    case OP_INT_LE:
      printf("INT_LE ");

      putchar('\n');
      break;

    case OP_INT_GE:
      printf("INT_GE ");

      putchar('\n');
      break;

    case OP_INT_ADD:
      printf("INT_ADD ");

      putchar('\n');
      break;

    case OP_INT_SUB:
      printf("INT_SUB ");

      putchar('\n');
      break;

    case OP_INT_MUL:
      printf("INT_MUL ");

      putchar('\n');
      break;

    case OP_INT_DIV:
      printf("INT_DIV ");

      putchar('\n');
      break;

    case OP_INT_MINUS:
      printf("INT_MINUS ");

      putchar('\n');
      break;

    case OP_DBL_LT:
      printf("DBL_LT ");

      putchar('\n');
      break;

    case OP_DBL_GT:
      printf("DBL_GT ");

      putchar('\n');
      break;

    case OP_DBL_LE:
      printf("DBL_LE ");

      putchar('\n');
      break;

    case OP_DBL_GE:
      printf("DBL_GE ");

      putchar('\n');
      break;

    case OP_DBL_EQ:
      printf("DBL_EQ ");

      putchar('\n');
      break;

    case OP_DBL_NEQ:
      printf("DBL_NEQ ");

      putchar('\n');
      break;

    case OP_DBL_ADD:
      printf("DBL_ADD ");

      putchar('\n');
      break;

    case OP_DBL_SUB:
      printf("DBL_SUB ");

      putchar('\n');
      break;

    case OP_DBL_MUL:
      printf("DBL_MUL ");

      putchar('\n');
      break;

    case OP_DBL_DIV:
      printf("DBL_DIV ");

      putchar('\n');
      break;

    case OP_DBL_MINUS:
      printf("DBL_MINUS ");

      putchar('\n');
      break;

    case OP_STR_EQ:
      printf("STR_EQ ");

      putchar('\n');
      break;
    case OP_STR_NEQ:
      printf("STR_NEQ ");

      putchar('\n');
      break;
    case OP_STR_LT:
      printf("STR_LT ");

      putchar('\n');
      break;
    case OP_STR_LE:
      printf("STR_LE ");

      putchar('\n');
      break;
    case OP_STR_GT:
      printf("STR_GT ");

      putchar('\n');
      break;
    case OP_STR_GE:
      printf("STR_GE ");

      putchar('\n');
      break;

    case OP_CONTAINS:
      printf("CONTAINS ");

      putchar('\n');
      break;
    case OP_ICONTAINS:
      printf("ICONTAINS ");

      putchar('\n');
      break;
    case OP_STARTSWITH:
      printf("STARTSWITH ");

      putchar('\n');
      break;
    case OP_ISTARTSWITH:
      printf("ISTARTSWITH ");

      putchar('\n');
      break;
    case OP_ENDSWITH:
      printf("ENDSWITH ");

      putchar('\n');
      break;
    case OP_IENDSWITH:
      printf("IENDSWITH ");

      putchar('\n');
      break;
    case OP_IEQUALS:
      printf("IEQUALS ");

      putchar('\n');
      break;

    default:
      YR_DEBUG_FPRINTF(
          2, stderr, "- case <unknown instruction>: // %s()\n", __FUNCTION__);
      // Unknown instruction, this shouldn't happen.
      assert(false);
    }
  }

  puts("=================== STOP ===================");
  return result;
}