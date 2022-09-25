#include <yara/modules.h>
#include <inttypes.h>

#define MODULE_NAME parseutils

define_function(print_int_data)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  YR_OBJECT* module = yr_module();

  int64_t offset_0 = integer_argument(1);
  int64_t size = integer_argument(2);
  uint8_t data[size];
    
  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = block->fetch_data(block);
    int t = 0;
    for (size_t i = offset_0; i<offset_0+size; i++)
    {
      uint8_t c = *(block_data + i);
      data[t] = c;
      t++;
    }
  }

  char str[size];
  int index = 0;
  for(int i=0; i< size; i++)
    index += sprintf(&str[index], "%d ", data[i]);
  
  yr_set_string(str,module,"str");
  return_string(str);
}

define_function(print_string_data)
{
  YR_SCAN_CONTEXT* context = yr_scan_context();
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;
  YR_OBJECT* module = yr_module();

  int64_t offset_0 = integer_argument(1);
  int64_t size = integer_argument(2);
  uint8_t data[size];
    
  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = block->fetch_data(block);
    int t = 0;
    for (size_t i = offset_0; i<offset_0+size; i++)
    {
      uint8_t c = *(block_data + i);
      data[t] = c;
      t++;
    }
  }

  char str[size];
  int index = 0;
  for(int i=0; i< size; i++)
    index += snprintf(&str[index], size-index+1, "%c", data[i]);

  yr_set_string(str,module,"str");
  return_string(str);
}

begin_declarations

  declare_function("print_string_data","ii","s",print_string_data);
  declare_function("print_int_data","ii","s",print_int_data);

end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}



int module_load(YR_SCAN_CONTEXT* context, YR_OBJECT* module_object, void* module_data, size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

#undef MODULE_NAME