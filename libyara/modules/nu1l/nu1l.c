#include <yara/modules.h>

#define MODULE_NAME nu1l

define_function(do1)
{
  return_integer(1);
}

define_function(do2)
{
  return_integer(1);
}

define_function(key)
{
  return_integer(1);
}

begin_declarations

  declare_integer("_len");
  declare_integer("fmt");
  declare_integer_array("IN");
  declare_integer_array("buf");
  declare_function("do1", "sii", "i", do1);
  declare_function("do2", "ii", "i", do1);
  declare_function("key", "", "i", key);
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
