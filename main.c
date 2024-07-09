#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>

#define SLOWNIK "slownik.txt"
#define PLIK "crack5.txt"

// Wpisz liczbe watkow
#define NUM_THREADS 4

char md5Entries[10000000][33];
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
int foundPassword = 0;
int MD5_ENT = 0;
int MAX_ENTRIES = 0;

void bytes2md5(const char *data, int len, char *md5buf) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_md5();
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len, i;
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);
    for (i = 0; i < md_len; i++) {
        snprintf(&(md5buf[i * 2]), 16 * 2, "%02x", md_value[i]);
    }
}

struct Entry {
    int number;
    char email[50];
    char hashedPassword[33];
    char login[33];
};

struct ThreadData {
    char **words;
    int wordCount;
    int entryCount;
    struct Entry *entries;
};

void generateAndCheckVariations(const char *baseWord, const char *label, int entryCount, struct Entry *entries) {
    char md5[33];
    char modifiedWord[40];

    // Bez prefiksu i postfixu
    bytes2md5(baseWord, strlen(baseWord), md5);

    for (int j = 0; j < entryCount; j++) {
        if (strcmp(md5, entries[j].hashedPassword) == 0) {
            printf("Email: %s, Hasło: %s\n", entries[j].email, baseWord);
        }
    }

    // Z prefiksem
    for (int prefix = 0; prefix <= 9; prefix++) {
        snprintf(modifiedWord, sizeof(modifiedWord), "%d%s", prefix, baseWord);
        bytes2md5(modifiedWord, strlen(modifiedWord), md5);
        //printHashInfo(label, md5, modifiedWord);

        for (int j = 0; j < entryCount; j++) {
            if (strcmp(md5, entries[j].hashedPassword) == 0) {
                printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                }
        }

        // Z prefiksem i pierwszą wielką literą
        if (isalpha(baseWord[0])) {
            modifiedWord[0] = toupper(modifiedWord[0]);
            bytes2md5(modifiedWord, strlen(modifiedWord), md5);

            for (int j = 0; j < entryCount; j++) {
                if (strcmp(md5, entries[j].hashedPassword) == 0) {
                    printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                }
            }
        }
    }

    // Z prefiksem double
    for (int prefix = 0; prefix <= 99; prefix++) {
        snprintf(modifiedWord, sizeof(modifiedWord), "%02d%s", prefix, baseWord);
        bytes2md5(modifiedWord, strlen(modifiedWord), md5);
        //printHashInfo(label, md5, modifiedWord);

        for (int j = 0; j < entryCount; j++) {
            if (strcmp(md5, entries[j].hashedPassword) == 0) {
                printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
            }
        }

        // Z prefiksem double i pierwszą wielką literą
        if (isalpha(baseWord[0])) {
            modifiedWord[0] = toupper(modifiedWord[0]);
            bytes2md5(modifiedWord, strlen(modifiedWord), md5);

            for (int j = 0; j < entryCount; j++) {
                if (strcmp(md5, entries[j].hashedPassword) == 0) {
                    printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                }
            }
        }
    }

    // Z postfixem
    for (int postfix = 0; postfix <= 9; postfix++) {
        snprintf(modifiedWord, sizeof(modifiedWord), "%s%d", baseWord, postfix);
        bytes2md5(modifiedWord, strlen(modifiedWord), md5);
        //printHashInfo(label, md5, modifiedWord);

        for (int j = 0; j < entryCount; j++) {
            if (strcmp(md5, entries[j].hashedPassword) == 0) {
                printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
            }
        }

        // Z postfixem i pierwszą wielką literą
        if (isalpha(baseWord[0])) {
            modifiedWord[0] = toupper(modifiedWord[0]);
            bytes2md5(modifiedWord, strlen(modifiedWord), md5);

            for (int j = 0; j < entryCount; j++) {
                if (strcmp(md5, entries[j].hashedPassword) == 0) {
                    printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                }
            }
        }
    }

    // Z postfixem double
    for (int postfix = 0; postfix <= 99; postfix++) {
        snprintf(modifiedWord, sizeof(modifiedWord), "%s%02d", baseWord, postfix);
        bytes2md5(modifiedWord, strlen(modifiedWord), md5);
        //printHashInfo(label, md5, modifiedWord);

        for (int j = 0; j < entryCount; j++) {
            if (strcmp(md5, entries[j].hashedPassword) == 0) {
                printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
            }
        }

        // Z postfixem double i pierwszą wielką literą
        if (isalpha(baseWord[0])) {
            modifiedWord[0] = toupper(modifiedWord[0]);
            bytes2md5(modifiedWord, strlen(modifiedWord), md5);

            for (int j = 0; j < entryCount; j++) {
                if (strcmp(md5, entries[j].hashedPassword) == 0) {
                    printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                }
            }
        }
    }

    // Z prefiksem i postfixem
    for (int prefix = 0; prefix <= 9; prefix++) {
        for (int postfix = 0; postfix <= 9; postfix++) {
            snprintf(modifiedWord, sizeof(modifiedWord), "%d%s%d", prefix, baseWord, postfix);
            bytes2md5(modifiedWord, strlen(modifiedWord), md5);
            //printHashInfo(label, md5, modifiedWord);

            for (int j = 0; j < entryCount; j++) {
                if (strcmp(md5, entries[j].hashedPassword) == 0) {
                    printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                }
            }

            // Z prefiksem i postfixem i pierwszą wielką literą
            if (isalpha(baseWord[0])) {
                modifiedWord[0] = toupper(modifiedWord[0]);
                bytes2md5(modifiedWord, strlen(modifiedWord), md5);

                for (int j = 0; j < entryCount; j++) {
                    if (strcmp(md5, entries[j].hashedPassword) == 0) {
                        printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                    }
                }
            }
        }
    }

// Z prefiksem i postfixem double
for (int prefix = 0; prefix <= 99; prefix++) {
    for (int postfix = 0; postfix <= 99; postfix++) {
        snprintf(modifiedWord, sizeof(modifiedWord), "%02d%s%02d", prefix, baseWord, postfix);
        bytes2md5(modifiedWord, strlen(modifiedWord), md5);
        //printHashInfo(label, md5, modifiedWord);

        for (int j = 0; j < entryCount; j++) {
            if (strcmp(md5, entries[j].hashedPassword) == 0) {
                printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
            }
        }

        // Z prefiksem double i pierwszą wielką literą
        if (isalpha(baseWord[0])) {
            modifiedWord[2] = toupper(modifiedWord[2]);
            bytes2md5(modifiedWord, strlen(modifiedWord), md5);

            for (int j = 0; j < entryCount; j++) {
                if (strcmp(md5, entries[j].hashedPassword) == 0) {
                    printf("Email: %s, Hasło: %s\n", entries[j].email, modifiedWord);
                }
            }
        }
    }
}

}



void printHashInfo(const char *label, const char *hash, const char *word) {
    printf("%s Hash: %s, Word: %s\n", label, hash, word);
}

void *workerThread(void *arg) {
    struct ThreadData *threadData = (struct ThreadData *)arg;

    while (1) {
        pthread_mutex_lock(&mutex);

        if (foundPassword >= threadData->wordCount) {
            pthread_mutex_unlock(&mutex);
            break; 
        }

        int currentWordIndex = foundPassword;
        foundPassword++;

        pthread_mutex_unlock(&mutex);

        char lowerCaseWord[33];
        char upperCaseWord[33];

        strcpy(lowerCaseWord, threadData->words[currentWordIndex]);
        strcpy(upperCaseWord, threadData->words[currentWordIndex]);

        for (int k = 0; lowerCaseWord[k]; k++) {
            lowerCaseWord[k] = tolower(lowerCaseWord[k]);
        }

        for (int k = 0; upperCaseWord[k]; k++) {
            upperCaseWord[k] = toupper(upperCaseWord[k]);
        }

     /*   generateAndCheckVariations(lowerCaseWord, "Lowercase", threadData->entryCount, threadData->entries);

        if (isalpha(upperCaseWord[0])) {
            upperCaseWord[0] = toupper(upperCaseWord[0]);
            generateAndCheckVariations(upperCaseWord, "Mixedcase", threadData->entryCount, threadData->entries);
        }*/
    }

    return NULL;
}


void sigHandler(int signo) {
    if (signo == SIGHUP) {
        printf("\nZnalezione hasla:\n");
    }
    exit(0);
}

int main() {
    signal(SIGHUP, sigHandler);

    char **words = NULL;
    struct Entry *entries = NULL;
    FILE *fptrWords, *fptrEntries;
    int wordCount = 0, entryCount = 0;

    // Liczenie liczby wpisów w słowniku
    if ((fptrWords = fopen(SLOWNIK, "r")) == NULL) {
        printf("Błąd otwarcia pliku z wyrazami!\n");
        exit(1);
    }

    char buffer[33];
    while (fgets(buffer, sizeof(buffer), fptrWords) != NULL) {
        wordCount++;
    }

    rewind(fptrWords);  // przewinięcie pliku do początku

    // Alokacja pamięci dla słownika
    words = (char **)malloc(wordCount * sizeof(char *));
    for (int i = 0; i < wordCount; i++) {
        words[i] = (char *)malloc(33 * sizeof(char));
    }

    int i = 0;
    while (fgets(words[i], 33, fptrWords) != NULL) {
        size_t length = strlen(words[i]);
        if (length > 0 && words[i][length - 1] == '\n') {
            words[i][length - 1] = '\0';
        }
        i++;
    }

    fclose(fptrWords);

    // Liczenie liczby haseł w pliku
    if ((fptrEntries = fopen(PLIK, "r")) == NULL) {
        printf("Błąd otwarcia pliku z hasłami!\n");
        exit(1);
    }

    char line[100];
    while (fgets(line, sizeof(line), fptrEntries) != NULL) {
        entryCount++;
    }

    rewind(fptrEntries);

    // Alokacja pamięci dla haseł
    entries = (struct Entry *)malloc(entryCount * sizeof(struct Entry));

    i = 0;
    while (i < entryCount && fgets(line, sizeof(line), fptrEntries) != NULL) {
        sscanf(line, "%d %32s %49s %32s", &entries[i].number, entries[i].hashedPassword,
               entries[i].email, entries[i].login);
        i++;
    }

    fclose(fptrEntries);

    int numThreads = NUM_THREADS;
    pthread_t threads[numThreads];
    struct ThreadData threadData = {words, wordCount, entryCount, entries};

    for (int i = 0; i < numThreads; i++) {
        pthread_create(&threads[i], NULL, workerThread, (void *)&threadData);
    }

    for (int i = 0; i < numThreads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Zwolnienie pamięci
    for (int i = 0; i < wordCount; i++) {
        free(words[i]);
    }
    free(words);
    free(entries);

    return 0;
}


