#include "mytypes.h"


typedef struct {
	u32 original_key;
	u8 data[32];
} HashMapItem;

#define DEFAULT_HASH_MAP_LEN 512
typedef struct {
  HashMapItem items[DEFAULT_HASH_MAP_LEN];
} HashMap;

u16 hashKey(u32 key) {
  return key % DEFAULT_HASH_MAP_LEN;
}

// stores the first 32 bytes of `data[]` in `map`
// 0 = worked
// -1 = invalid key error
i8 hashMapStore(HashMap* map, u32 key, u8 data[]) {
  if (key == 0) {
    return -1;
  }
  u16 index = hashKey(key);
  if (map->items[index].original_key == 0) {
    map->items[index].original_key = key;
    for (u8 i = 0; i<32; i++) {
      map->items[index].data[i] = data[i];
    }
  }
  return 0;
}
