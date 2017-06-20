#include <cs50.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include <stdlib.h>

//struct to hold one block size input stream , 
//key and an index to keep track of the i/p stream
typedef struct blockData_t
{
    char *buffIn;
    char *key;
    long double idx;
    struct blockData_t *next;
}blockData_t;

//head to the linked list of i/p blocks
blockData_t *listHead = NULL;
//mutex to protect the linked list access from each thread
pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;

//A parameter to maintain the sync of the printing of each encrypted block
long double syncIndex = 0;
//mutex to protect the above index
pthread_mutex_t index_mutex = PTHREAD_MUTEX_INITIALIZER;

//parameter to indicate end of read from stdin to the running threads
bool emptyList = false;

//thread function which does the encryption and prints the encrypted block to stdout
void *encryptBuffer(void *vargs);
//Function to do the left shift of xor key
void shiftLeftOfKey(char *key);
//Function to add node to the linked list
void addBlockToLinkedList(char *key,char *buffer,int idx);
//int get_cpu_id();

int main(int argc,char *argv[])
{
    int iloop=0,noOfThreads = 0;
    FILE *fpk;//File handler for the key file
    char *key;//array pointer to hold the xor key
    char *buffer = NULL;//buffer to hold each block of data from the file
    pthread_t *tid;//pointer to the array of thread ids
    long double idx=0;
    int keySize;
    struct stat st;//to obtain the size of the keyFile
    
    //parsing the command line
    if(argc != 5)
    {
        fprintf(stderr,"ERR: wrong number of arguments\n");
        fprintf(stderr,"ERR: usage: ./encrypt -n [noofthreads] -k [keyfile]\n");
        return 1;
    }
    
    if(strcmp(argv[1],"-n") || strcmp(argv[3],"-k") )
    {
        fprintf(stderr,"ERR: usage: ./encrypt -n [noofthreads] -k [keyfile]\n");
        return 1;
    }
    
    noOfThreads = atoi(argv[2]);

    tid = (pthread_t *)malloc(noOfThreads * sizeof(pthread_t));
    
    //creating a pool of threads
    for(iloop=0;iloop<noOfThreads;iloop++)
    {
        if(pthread_create(&tid[iloop],NULL,encryptBuffer,NULL))
        {
            fprintf(stderr,"ERR: thread creation error\n");
            return 1;
        }
    }
    
    if(!(fpk = fopen(argv[4],"r")))
    {
        fprintf(stderr,"ERR: Unable to open key file\n");
        return 1;
    }
    
    //getting the block size which is the size of key
    stat(argv[4], &st);
    keySize = st.st_size; 
    key = malloc(keySize*sizeof(char));
    fread(key,1,keySize,fpk);
    
    //buffer to read each i/p block
    buffer = (char*)malloc(keySize*sizeof(char));
     
    while(fread(buffer,1,keySize,stdin) > 0)
    {
        addBlockToLinkedList(key,buffer,idx);
        shiftLeftOfKey(key);
        memset(buffer,'\0',sizeof(buffer));
        idx++;// index to maintain the order of the blocks 
    }
    emptyList = true; // to mark the end of Input from stdin
    
    fclose(fpk);

    //wait for the threads to complete execution   
    for(iloop=0;iloop< noOfThreads;iloop++)
    {
        pthread_join(tid[iloop],NULL);
    }
}

void *encryptBuffer(void *vargs)
{
    blockData_t blockData;//temporary buffer to store input block and key and the index to the current block
    blockData_t *tempNode;
    bool skipEnc = false;

    while(1)
    {
        pthread_mutex_lock(&list_mutex);
        skipEnc = false;

        //read one data block ,key and index to the block from the linked list
        //and remove that node from the linked list and update the head of the list
        if(listHead != NULL)
        {
            blockData.buffIn = (char *)malloc(strlen(listHead->buffIn)*sizeof(char));
            memcpy(blockData.buffIn,listHead->buffIn,strlen(listHead->buffIn)+1);
            blockData.key  = (char *)malloc(strlen(listHead->key)*sizeof(char));
            memcpy(blockData.key ,listHead->key,strlen(listHead->key)+1);
            blockData.idx = listHead->idx;
            tempNode = listHead->next;
            free(listHead);
            listHead = tempNode;
        }
        else
        {
            skipEnc = true;//no encryption if there is no block
        }
            
        pthread_mutex_unlock(&list_mutex);
    
        //encryption algorithm
        if(skipEnc == false)
        {
            int blockSize = strlen(blockData.buffIn);
            char *buffOp = (char *)malloc(blockSize*sizeof(char));
            int i;
            //length of the buffIn may be shorter than that of the key
            for(i=0;i < blockSize;i++)
            {
               buffOp[i] = blockData.buffIn[i] ^ blockData.key[i];
            }
            
            //waiting for the threads to print the encrypted block in the order they were read
            while(blockData.idx != syncIndex);
            pthread_mutex_lock(&index_mutex);
            fwrite(buffOp,1,blockSize,stdout);
            //increment by 1 so that the next encrypted block holding the next index value could be printed 
            syncIndex = blockData.idx+1;
            pthread_mutex_unlock(&index_mutex);
            memset(buffOp,'\0',sizeof(buffOp));
            free(buffOp);
            free(blockData.buffIn);
            free(blockData.key);
            
        }
        else
        {
            if(emptyList == true)
            {
                 return NULL;
            }
        }
    }
}

void shiftLeftOfKey(char *key)
{
    int carry_cur,carry,i;
    
    carry = key[0]&0x80?1:0;//saving the MSB for rotation
    
    for(i=0;i<strlen(key);i++)
    {
        if(i == strlen(key) -1 )
            carry_cur = carry;
        else
            carry_cur = key[i+1]&0x80?1:0;
            
        key[i] = key[i]<<1|carry_cur;
    }
 
}

void addBlockToLinkedList(char *key,char *buffer,int idx)
{
    blockData_t *Node = (blockData_t*)malloc(sizeof(blockData_t));

    pthread_mutex_lock(&list_mutex);
    blockData_t *tempNode = listHead;
    blockData_t *temphead = NULL;
    //add data block to the linked list while the mutex is locked
    Node->buffIn = (char *)malloc(strlen(buffer)*sizeof(char));
    memcpy(Node->buffIn,buffer,strlen(buffer)+1);
    Node->key = (char *)malloc(strlen(key)*sizeof(char));
    memcpy(Node->key,key,strlen(key)+1);
    Node->idx    = idx;
    Node->next   = NULL;
    

    if(tempNode == NULL)
    {
        listHead = Node;
    }
    else
    {
        while(tempNode->next)
        {
             tempNode = tempNode->next;
        }
        tempNode->next = Node;
    }
    pthread_mutex_unlock(&list_mutex);
}

