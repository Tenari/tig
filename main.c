/*
 * Code conventions:
 *  MyStructType
 *  myFunction()
 *  my_variable
 *  MY_CONSTANT
 * */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include "mytypes.h"

#define RESET   "\033[0m"
#define BLACK   "\033[30m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"

#define HASH_LEN 32
void checksumAndStage(ptr filepath);
void printHash(u8 hash[32]);

bool isDirectory(const ptr path) {
  struct stat path_stat;
  if (stat(path, &path_stat) != 0) {
    return false; // If stat() fails, the path is not valid
  }
  return S_ISDIR(path_stat.st_mode); // Check if the path is a directory
  //return S_ISREG(path_stat.st_mode); // Check if the path is a regular file
}

#define COPY_BUFSIZE 128
void copy(FILE *in, FILE *out) {
    u8 buf[COPY_BUFSIZE];
    u64 numread, numwrite;

    while (!feof(in)) {
        numread = fread(buf, sizeof(u8), COPY_BUFSIZE, in);

        if (numread > 0) {
            numwrite = fwrite(buf, sizeof(u8), numread, out);

            if (numwrite != numread) {
                fputs("mismatch!\n", stderr);
                return;
            }
        }
    }
}

i32 init() {
  struct stat st = {0};

  if (stat(".tig", &st) == -1) {
    i32 result = mkdir(".tig", 0755);
    result = result | mkdir(".tig/staging", 0755);
    fopen(".tig/staging/.index", "w");
    if (result == 0) {
      puts("Initialized new tig repository");
    }
    return result;
  } else {
    puts("you already initialized here");
    return -1;
  }
}

// move the files matching `filepath` into the "staging area"
//  by checksumming them and saving the mapping of filename -> checksum in "staging area"
i32 add(ptr filepath) {
  //FILE *master_head = fopen(".tig/refs/heads/master", "w");
  if (isDirectory(filepath)) {
    // loop through all files in the directory, recursively
    /*DIR *dp;
    struct dirent *ep;
    dp = opendir ("./");
    if (dp != NULL) {
      while ((ep = readdir(dp)) != 0) {
        puts(ep->d_name);
      }
      (void) closedir(dp);
    } else {
      perror("Couldn't open the directory");
      return -1;
    } */
  } else {
    checksumAndStage(filepath);
  }

  return 0;
}

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))
typedef struct {
	u8 data[64];
	u32 datalen;
	u64 bitlen;
	u32 state[8];
} Sha256State;
static const u32 k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256Transform(Sha256State *state, const u8 data[]) {
	u32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = state->state[0];
	b = state->state[1];
	c = state->state[2];
	d = state->state[3];
	e = state->state[4];
	f = state->state[5];
	g = state->state[6];
	h = state->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	state->state[0] += a;
	state->state[1] += b;
	state->state[2] += c;
	state->state[3] += d;
	state->state[4] += e;
	state->state[5] += f;
	state->state[6] += g;
	state->state[7] += h;
}

Sha256State sha256Init() {
  Sha256State state = {0};
  state.datalen = 0;
	state.bitlen = 0;
	state.state[0] = 0x6a09e667;
	state.state[1] = 0xbb67ae85;
	state.state[2] = 0x3c6ef372;
	state.state[3] = 0xa54ff53a;
	state.state[4] = 0x510e527f;
	state.state[5] = 0x9b05688c;
	state.state[6] = 0x1f83d9ab;
	state.state[7] = 0x5be0cd19;
  return state;
}

void sha256AddByte(Sha256State *state, u8 byte) {
    state->data[state->datalen] = byte;
    state->datalen++;
    if (state->datalen == 64) {
      sha256Transform(state, state->data);
      state->bitlen += 512;
      state->datalen = 0;
    }
}

// sets passed in `hash` to the finialized BE hash bytes based on the `state`
void sha256Finish(Sha256State *state, u8 hash[]) {
  memset(hash, 0, HASH_LEN);
	u32 i = state->datalen;

	// Pad whatever data is left in the buffer.
	if (state->datalen < 56) {
		state->data[i++] = 0x80;
		while (i < 56)
			state->data[i++] = 0x00;
	} else {
		state->data[i++] = 0x80;
		while (i < 64)
			state->data[i++] = 0x00;
		sha256Transform(state, state->data);
		memset(state->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	state->bitlen += state->datalen * 8;
	state->data[63] = state->bitlen;
	state->data[62] = state->bitlen >> 8;
	state->data[61] = state->bitlen >> 16;
	state->data[60] = state->bitlen >> 24;
	state->data[59] = state->bitlen >> 32;
	state->data[58] = state->bitlen >> 40;
	state->data[57] = state->bitlen >> 48;
	state->data[56] = state->bitlen >> 56;
	sha256Transform(state, state->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		hash[i]      = (state->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (state->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (state->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (state->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (state->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (state->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (state->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (state->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
  //printHash(hash);
}

// fills `hash[]` with checksum of file contents at `filepath`
void checksumFile(ptr filepath, u8 hash[]) {
  FILE *file = fopen(filepath, "r");
  Sha256State state = sha256Init();
  u8 buf[COPY_BUFSIZE];
  u64 numread, numwrite = 0;
  // loop through the file
  while (!feof(file)) {
    numread = fread(buf, sizeof(u8), COPY_BUFSIZE, file);
    if (numread > 0) {
      // keep hashing the file
      for (u32 i = 0; i < numread; ++i) {
        sha256AddByte(&state, buf[i]);
      }
    }
  }

  sha256Finish(&state, hash);
  //printHash(hash);
}

void checksumAndStage(ptr filepath) {
  // open the file
  FILE *file = fopen(filepath, "r");
  char backup_path[2048] = ".tig/staging/";
  strcat(backup_path, filepath);
  FILE *backup = fopen(backup_path, "w");
  // init the Sha256State
  // init the copy buffer and counters
  Sha256State state = sha256Init();
  u8 buf[COPY_BUFSIZE];
  u64 numread, numwrite = 0;

  // loop through the file
  while (!feof(file)) {
    numread = fread(buf, sizeof(u8), COPY_BUFSIZE, file);
    if (numread > 0) {
      // keep hashing the file
      for (u32 i = 0; i < numread; ++i) {
        sha256AddByte(&state, buf[i]);
      }

      // copy the file to the staging area
      numwrite = fwrite(buf, sizeof(u8), numread, backup);
      if (numwrite != numread) {
        fputs("mismatch!\n", stderr);
        return;
      }
    }
  }

  u8 hash[HASH_LEN] = {0};
  sha256Finish(&state, hash);

  FILE* index = fopen(".tig/staging/.index", "a");
  fwrite(hash, sizeof(u8), HASH_LEN, index);
  fwrite(filepath, sizeof(u8), strlen(filepath), index);
  fwrite("\n", sizeof(u8), 1, index);
  //printHash(hash);
}

void printHash(u8 hash[HASH_LEN]) {
  for (u8 i = 0; i < HASH_LEN; i++) {
    printf("%02X", hash[i]);
  }
}

#define LINEBUF_LEN 2048
// -1 = error opening file
i32 status() {
  FILE* index = fopen(".tig/staging/.index", "r");
  if (index == NULL) {
    perror("Error opening file");
    return -1;
  }

  char linebuf[LINEBUF_LEN] = {0};

  // for each line in the "staged index":
  // - get hash and filename
  // - compare hash to current file-hash, to print file's status
  while (fgets(linebuf, LINEBUF_LEN, index)) {
    u8 hash[HASH_LEN];
    char filename[LINEBUF_LEN] = {0};
    for (u8 i = 0; i < HASH_LEN; i++) {
      hash[i] = linebuf[i];
    }
    for (u16 i = 0; linebuf[i+HASH_LEN] != '\n'; i++) {
      filename[i] = linebuf[i + HASH_LEN];
    }
    u8 current_hash[HASH_LEN];
    checksumFile(filename, current_hash);
    // if the hashes match, nothing has changed
    if (memcmp(current_hash, hash, HASH_LEN) == 0) {
      printf("ready to commit:" GREEN " %s\n" RESET, filename);
    } else {
      printf("unstaged changes:" RED " %s\n" RESET, filename);
    }
  }

  if (ferror(index)) {
      perror("An error occurred.\n");
      return -2;
  }

  fclose(index);
  return 0;
}

i32 main(i32 argc, ptr argv[]) {
  if (argc == 1) {
    puts("`git init`    to start");
    puts("git add .     to add files to version control");
    return 0;
  }
  if (strcmp(argv[1], "init") == 0) {
    return init();
  } else if (strcmp(argv[1], "add") == 0) {
    if (argc <= 2) {
      puts("You must pass a filepath so I know what to add");
      return -1;
    } else {
      return add(argv[2]);
    }
  } else if (strcmp(argv[1], "commit") == 0) {
    puts("commit not implemented yet");
    return -1;
  } else if (strcmp(argv[1], "status") == 0) {
    return status();
  }
  return 0;
}
