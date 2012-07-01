/*
 * Copyright 2012 Yoshihisa Tanaka
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>

#include "defs.h"

#define PACKET_LENGTH 188

typedef unsigned char byte;

static void usage(void);
boolean file_exists(const char *filename);
boolean yes_or_no(const char *msg, boolean default_);
int get_pid(const byte *data);
int getseclen(const byte *data);
int find(int value, const int *array, int len);
unsigned int crc32(const byte* data, int len);

int main(int argc, char** argv) {
    FILE *in, *out;
    int pmt = 0, pid;
    int *pids = NULL, pidc = 0;
    byte buf[PACKET_LENGTH];
    byte z[PACKET_LENGTH - 5];
    unsigned int crc;
    int i, Nall, N;
    int opt;
    const char *input_filename = NULL;
    const char *output_filename = NULL;
    boolean force_flag = false;
    int fd;

    /* 引数の解析 */
    while ((opt =  getopt(argc, argv, "i:o:fh")) != - 1) {
        switch (opt) {
        case 'i':
            input_filename = optarg;
            break;
        case 'o':
            output_filename = optarg;
            break;
        case 'f':
            force_flag = true;
            break;
        case 'h':
        default:
            usage();
        }
    }

    argc -= optind;
    argv += optind;

    /* 引数チェック */
    if (input_filename != NULL && !file_exists(input_filename)) {
        fprintf(stderr, "ERROR: input file not exists: %s\n",
                input_filename);
        usage();
    }

    if (output_filename != NULL && !force_flag && file_exists(output_filename)) {
        if (input_filename == NULL) {
            fprintf(stderr, "ERROR: output file already exists: %s\n",
                    output_filename);
            usage();
        }

        fprintf(stderr, "output file already exists: %s\n", output_filename);
        if (!yes_or_no("overwrite?", false))
            usage();
    }

    /* 入力を開く */
    if (input_filename == NULL) {
        if ((fd = dup(fileno(stdin))) == -1 ||
            (in = fdopen(fd, "rb")) == NULL) {
            fprintf(stderr, "ERROR: cannot open stdin");
            exit(EXIT_FAILURE);
        }
    } else {
        if ((in = fopen(input_filename, "rb")) == NULL) {
            fprintf(stderr, "ERROR: cannot open input file: %s\n", input_filename);
            exit(EXIT_FAILURE);
        }
    }

    /* 出力を開く */
    if (output_filename == NULL) {
        if ((fd = dup(fileno(stdout))) == -1 ||
            (out = fdopen(fd, "wb")) == NULL) {
            fprintf(stderr, "ERROR: cannot open stdout");
            exit(EXIT_FAILURE);
        }
    } else {
        if ((out = fopen(output_filename, "wb")) == NULL) {
            fprintf(stderr, "ERROR: cannot open output file: %s\n", output_filename);
            exit(EXIT_FAILURE);
        }
    }

    /* 抽出対象を解析 */
    while (true) {
        if (fread(buf, sizeof(byte), PACKET_LENGTH, in) == 0)
            break;

        pid = get_pid(buf + 1);

        /* PAT */
        if (pid == 0x0000) {
            pmt = get_pid(buf + 19);
            /* PATのPMT1のみ残した差し替えデータを作成 */
            memcpy(z, buf + 5, 16);
            /* セクション長を0x11で上書き */
            z[2] = 0x11;
            /* CRC計算 */
            crc = crc32(z, 16);

            z[16] = (crc >> 24) & 0xFF;
            z[17] = (crc >> 16) & 0xFF;
            z[18] = (crc >> 8) & 0xFF;
            z[19] = crc & 0xFF;
            for (i = 20; i < PACKET_LENGTH - 5; i++)
                z[i] = 0xFF;
        } else if (pid == pmt) {
            /* PMT */
            Nall = getseclen(buf + 6);
            /* 残すPID数を計算 */
            pidc = 2;
            for (N = getseclen(buf + 15) + 16 + 1; N < Nall + 8 - 4; N += 4 + getseclen(buf + N + 3) + 1) {
                if (buf[N] != 0x0D)
                    pidc++;
            }
            pids = (int *)malloc(pidc * sizeof(int));

            /* PIDを配列に格納 */
            pids[0] = pmt;
            /* PCR */
            pids[1] = get_pid(buf + 13);
            /* EPID */
            i = 2;
            for (N = getseclen(buf + 15) + 16 + 1; N < Nall + 8 - 4; N += 4 + getseclen(buf + N + 3) + 1) {
                if (buf[N] != 0x0D)
                    pids[i++] = get_pid(buf + N + 1);
            }

            fprintf(stderr, "Extract pids");
            for (i = 0; i < pidc; i++)
                fprintf(stderr, ", 0x%04x", pids[i]);
            fprintf(stderr, "\n");
            break;
        }
    }

    /* 入力ファイルの先頭に戻す(入力をfifoにする場合はコメントアウト) */
    fseek(in, 0, SEEK_SET);

    while (true) {
        if (fread(buf, sizeof(byte), PACKET_LENGTH, in) == 0)
            break;

        pid = get_pid(buf + 1);

        /* PAT */
        if (pid == 0x0000) {
            /* 修正後のデータを出力 */
            fwrite(buf, sizeof(byte), 5, out);
            fwrite(z, sizeof(byte), PACKET_LENGTH - 5, out);
        } else if (find(pid, pids, pidc)) {
            fwrite(buf, sizeof(byte), PACKET_LENGTH, out);
        }
    }

    fclose(out);
    fclose(in);
    free(pids);

    return EXIT_SUCCESS;
}

void usage(void) {
    fprintf(stderr,
            "usage: tspick [-h] [-i INPUT_FILE] [-o OUTPUT_FILE]\n"
            );
    exit(EXIT_FAILURE);
}

int get_pid(const byte *data) {
    return ((data[0] & 0x1F) << 8) + data[1];
}

int getseclen(const byte *data) {
    return ((data[0] & 0x0F) << 8) + data[1];
}

int find(int value, const int *array, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (array[i] == value)
            return true;
    }
    return false;
}

unsigned int crc32(const byte *data, int len) {
    int crc = 0xFFFFFFFF;
    byte bit;
    int c, i;

    for (; len--; data++) {
        for (i = 0; i < 8; i++) {
            bit = (*data >> (7 - i)) & 0x1;
            c = 0;

            if (crc & 0x80000000)
                c = 1;

            crc = crc << 1;

            if (c ^ bit)
                crc ^= 0x04C11DB7;

            crc &= 0xFFFFFFFF;
        }
    }
    return crc;
}

int file_exists(const char *filename) {
    struct stat sb;
    return stat(filename, &sb) == 0 ? true : false;
}

boolean yes_or_no(const char *msg, boolean default_) {
    char buf[5];
    char ans;

    while (1) {
        fprintf(stderr, "%s (%s)\n", msg, default_ ? "Y/n" : "y/N");
        if (fgets(buf, sizeof(buf), stdin) == NULL)
            return false;

        if (strlen(buf) == 1)
            return default_;

        if (strlen(buf) == 2) {
            ans = tolower(buf[0]);
            if (ans == 'y')
                return true;
            if (ans == 'n')
                return false;
        }

        fflush(stdin);
    }
}
