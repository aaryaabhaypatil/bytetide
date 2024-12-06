#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>

// Getting to the folder
#include "../../include/chk/pkgchk.h"
#include "../../include/crypt/sha256.h"


#define MAX_PATH_LENGTH 200 
#define MAX_LENGTH 1050
#define SHA256_BFLEN (4096)
#define LENGTH 4096



// PART 1
// Helper fucntions

// helper fucntion for loading
// function for initialising the bpkg object
static struct bpkg_obj* create_bpkg_obj(void) {
    // allocates memory for the bpkg object
   struct bpkg_obj* obj = malloc(sizeof(struct bpkg_obj));
   // making sure that the memory has no uniinitialised data
   if (obj) {
       memset(obj, 0, sizeof(struct bpkg_obj));
   }
   return obj;
}


// this is used for reading chunks of data from a data file
// called in compute_completed_hashes
size_t read_chunk_data(FILE *file, char *buffer, uint32_t size) {
    // it reads the given size of data
    size_t bytes_read = fread(buffer, 1, size, file);
    // once it reads data, we do error checking
    if (bytes_read > 0) {
        return bytes_read;
    } else if (feof(file)) {
        // End of file reached.
    } else if (ferror(file)) {
        // Error reading from file
    } else {
        // Nothing was read from the file.
    }
    return 0;
}

// helper function for bpkg_get_completed_chunks and bpkg_get_min_completed_hashes
// function to compute completed chunks
size_t compute_completed_hashes(struct bpkg_obj *bpkg, FILE *file, struct bpkg_query *qry, int *path) {
    // index keeps track of the number of completed chunks
    size_t index = 0;
    // we go through every chunk in the bpkg file
    for (int i = 0; i < bpkg->nchunks; i++) {
        // we check if none of the fields of chunks are NULL or invalid
        if (bpkg->chunks[i]->hash != NULL && bpkg->chunks[i]->size > 0) {
            // we are reading size number of bytes, so we malloc that much memory
            char *buffer = malloc(bpkg->chunks[i]->size);
            // we call the fucntion to read data into the buffer
            size_t bytes_read = read_chunk_data(file, buffer, bpkg->chunks[i]->size);
            if (bytes_read > 0) {
                // these are used to compute the hash value of the chunk we read
                struct sha256_compute_data cdata = { 0 };
                uint8_t hashout[SHA256_INT_SZ] = { 0 };
                char final_hash[65] = { 0 };
                sha256_compute_data_init(&cdata);
                sha256_update(&cdata, buffer, bpkg->chunks[i]->size);
                sha256_finalize(&cdata, hashout);
                sha256_output_hex(&cdata, final_hash);
                // final_hash will store the computed hash of the chunk

                /* we check if the computed hash is equal to the expected hash, if it is it is 
                    completed */
                /* i have an integer array called path, which stores if the chunk at a given index 
                    is completed or not*/
                // it will store 1 if chunk[i] is completed, and 0 otherwise
                if (strcmp(final_hash, bpkg->chunks[i]->hash) == 0) {
                    path[i] = 1;
                    index += 1;
                }
            }
            free(buffer);
        }
    }
    return index;
}


// The following functions are helper functions for bpkg_get_all_chunk_hashes_from_hash

// This function check if the given hash is a chunks hash value
struct chunk* find_chunk_by_hash(struct bpkg_obj *bpkg, const char *hash) {
    for (uint32_t i = 0; i < bpkg->nchunks; i++) {
        if (strcmp(bpkg->chunks[i]->hash, hash) == 0) {
            /* if it is the same, then we return the chunk whose hash value matches 
                with the given hash*/
            return bpkg->chunks[i];
        }
    }
    return NULL;
}

// Function to find the index of a hash in the hashes array
int find_hash_index(struct bpkg_obj *bpkg, const char *hash) {
    for (uint32_t i = 0; i < bpkg->nhashes; i++) {
        if (strcmp(bpkg->hashes[i], hash) == 0) {
            // if the given hash matches with hashes[i], then we return i
            return i;
        }
    }
    // if theres no such hash, we return -1
    return -1;
}

// Add the chunks from a start index to an end index and add them to the qry
void collect_chunk_hashes(struct bpkg_query *qry, struct chunk **chunks, uint32_t start,
                            uint32_t end, size_t *count) {
    for (uint32_t i = start; i < end; i++) {
        qry->hashes[(*count)++] = strdup(chunks[i]->hash);
    }
}

// Function to compute the depth of a node at a given index
// This is for this function for getting chunk hashes from hash
int compute_depth(int index) {
    return (int)floor(log2(index + 1));
}

// function to calculate the number of hashes to return based on depth of a given node
int calculate_hashes_to_return(int nhashes, int depth) {
    return (nhashes + 1) / pow(2.0, depth);
}

// function to compute the path from the root to the given node
// we check which indices of the tree have een visited to determine the start index
void compute_path_to_root(int index, int *path, int *length) {
    *length = 0;
    // this will get the path from the node to the root
    while (index >= 0) {
        path[(*length)++] = index;
        if (index == 0) {
            break;
        }
        index = (index - 1) / 2;
    }
    // reverse the path so we have root to node
    for (int i = 0; i < *length / 2; ++i) {
        int temp = path[i];
        path[i] = path[*length - 1 - i];
        path[*length - 1 - i] = temp;
    }
}

/* in this we can get the start index of where the chunks should start from when 
we have to return the chunk hashes of a node*/
int calculate_start_index(int *path, int length, int nhashes) {
    int start_index = 0;
    for (int i = 0; i < length; ++i) {
        if (path[i] % 2 == 0) {
            // if we go to the right child in the tree, the start index adds y this value
            if (path[i] != 0) {
                start_index += (nhashes + 1) / pow(2, i);
            }
            // if we go to the left child, no changes in the start index
        }
    }
    return start_index;
}

// Given function
/**
 * Loads the package for when a value path is given
 */
struct bpkg_obj* bpkg_load(const char* path) {
    FILE *file = fopen(path, "r");
    if(!file) {
        // ERROR: Failed to open
        return NULL;
    }
    // initialising a bpkg obj
    struct bpkg_obj *obj = create_bpkg_obj();
    if(!obj) {
        fclose(file);
        return NULL;
    }

    // now we parse all the data from the file
    // initialising all the elements of the buffer array to 0
    char buffer[MAX_LENGTH] = {0};
    char *target1 = "chunks:\n";

    // reading the identifier
    fgets(buffer, sizeof(buffer), file);
    size_t len = strlen(buffer);
     // remove newline
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0'; 
    }
    sscanf(buffer + strlen("ident:"), "%s", obj->ident);

    // reading the filename
    fgets(buffer, sizeof(buffer), file);
     // remove newline
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';  
    }
    sscanf(buffer, "filename:%s", obj->filename);

    // reading size
    fgets(buffer, sizeof(buffer), file);
     // remove newline
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    sscanf(buffer, "size:%u", &obj->size);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0'; 
    }

    // reading the number of hashes
    fgets(buffer, sizeof(buffer), file);
    // remove newline
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0'; 
    }
    sscanf(buffer, "nhashes:%u", &obj->nhashes);


    // reading the hashes
    fgets(buffer, sizeof(buffer), file);
    // remove newline
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    // allocating memory for the hashes
    obj->hashes = (char **)malloc(obj->nhashes * sizeof(char *));
    if (obj->hashes == NULL) {
        // Error: Failed to allocate memory for hashes array
        return NULL;
    }
    // doing this for every hash
    for (uint32_t i = 0; i < obj->nhashes; i++) {
        // check if the current index is within bounds
        if (i >= obj->nhashes) {
            // Error: Array index out of bounds
            return NULL;
        }
        // allocate memory for each hash and check for successful allocation
        obj->hashes[i] = (char *)malloc(HASH_LENGTH);
        if (obj->hashes[i] == NULL) {
            // Error: Failed to allocate memory for hash
            return NULL;
        }
        // read a line from the file into buffer, the value of the hash
        if (fgets(buffer, sizeof(buffer), file) == NULL) {
            // Error: Failed to read hash from file
            return NULL;
        }
        // error checking for failed extraction of the hash value
        if (sscanf(buffer+1, "%64s", obj->hashes[i]) != 1) {
            // Error: Failed to extract hash from buffer
        }
    }

    // reading the number of chunks
    fgets(buffer, sizeof(buffer), file);
    // remove newline
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0'; 
    }
    sscanf(buffer, "nchunks:%u", &obj->nchunks);


    // this reads the value "chunks:", which ensures that the chunks start from the next line
    fgets(buffer, sizeof(buffer), file);
    if (strcmp(buffer, target1) == 0) {
        // new chunk struct for all the chunks
        struct chunk **new_chunks = (struct chunk **)malloc(obj->nchunks * 
                                    sizeof(struct chunk));
        // for every chunk
        for (uint32_t i = 0; i < obj->nchunks; i++) {
            struct chunk *new_chunk = (struct chunk *)malloc(sizeof(struct chunk));
            // read a line from the file into buffer
            if (fgets(buffer, sizeof(buffer), file) == NULL) {
                // Error: Failed to read hash from file
                return NULL;
            }
            // allocating memory for the hash field of chunks
            new_chunk->hash = (char *)malloc(HASH_LENGTH * sizeof(char));
            // setting the rest of the fields to 0 initially
            new_chunk->offset = 0;
            new_chunk->size = 0; 
            // stores the fields from the line read into buffer
            if (sscanf(buffer+1, "%64s,%u,%u", new_chunk->hash, &new_chunk->offset, 
                &new_chunk->size) != 3) {
                // error in parsing
                // free memory allocated for the chunk
                free(new_chunk->hash);
                free(new_chunk);
                return NULL;
            } else {
                // if successful, add the chunk to the chunk struct for all the chunks
                new_chunks[i] = new_chunk;
            }
        }
        // connecting all the chunks to the bpkg obj
        obj->chunks = new_chunks;
    }
    // after all the fields have been loaded, we return obj
    return obj;
}

/**
 * Checks to see if the referenced filename in the bpkg file
 * exists or not.
 * @param bpkg, constructed bpkg object
 * @return query_result, a single string should be
 *      printable in hashes with len sized to 1.
 * 		If the file exists, hashes[0] should contain "File Exists"
 *		If the file does not exist, hashes[0] should contain "File Created"
 */

struct bpkg_query bpkg_file_check(struct bpkg_obj* bpkg){
    // initialising the final result
    struct bpkg_query result;
    // we are only returning one value
    result.len = 1;
    // allocating memory for the result
    result.hashes = (char **)malloc(result.len * sizeof(char *));
    // error checking for memory allocation
    if (result.hashes == NULL) {
        // ERROR: Memory allocation failed
        result.len = 0;
        return result;
    }
    // allocating memory for the first hash string
    result.hashes[0] = (char *)malloc(MAX_FILENAME_LENGTH * sizeof(char));
    // error checking for memory allocation
    if (result.hashes[0] == NULL) {
        // ERROR: memory allocation failed for result.hashes[0]
        free(result.hashes);
        result.len = 0;
        return result;
    }
    // opened the file in read mode
    FILE *file = fopen(bpkg->filename, "r");
    if (file != NULL) {
        // if the file exists then we close the file
        strcpy(result.hashes[0], "File Exists");
        fclose(file);
    } else {
        strcpy(result.hashes[0], "File Created");
    }
    return result;
}


/**
 * Retrieves a list of all hashes within the package/tree
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_hashes(struct bpkg_obj* bpkg) {
    struct bpkg_query qry = { 0 };
    if (bpkg == NULL || bpkg->hashes == NULL) {
        return qry;
    }
    // total number of hashes will be the hashes in hashes and the hashes in chunks
    uint32_t total_hashes = bpkg->nhashes + bpkg->nchunks;
    // allocating memory for hashes
    qry.hashes = (char**)malloc(total_hashes * sizeof(char*));
    if (qry.hashes == NULL) {
        return qry;
    }
    // getting all the hashes from bpkg->hashes
    for (size_t i = 0; i < bpkg->nhashes; i++) {
        qry.hashes[i] = strdup(bpkg->hashes[i]);
        if (qry.hashes[i] == NULL) {
            // free allocated memory if strdup fails
            for (size_t j = 0; j < i; j++) {
                free(qry.hashes[j]);
            }
            free(qry.hashes);
            qry.hashes = NULL;
            return qry;
        }
    }
    size_t current_hash_index = bpkg->nhashes;
    // getting all the hashes from bpkg->chunks
    for (size_t i = 0; i < bpkg->nchunks; i++) {
        struct chunk* chunk = bpkg->chunks[i];
        qry.hashes[current_hash_index] = strdup(chunk->hash);
        if (qry.hashes[current_hash_index] == NULL) {
            // free allocated memory if strdup fails
            for (size_t k = bpkg->nhashes; k < current_hash_index; k++) {
                free(qry.hashes[k]);
            }
            free(qry.hashes);
            qry.hashes = NULL;
            return qry;
        }
        current_hash_index++;   
    }
    qry.len = total_hashes;
    return qry;
}



/**
 * Retrieves all completed chunks of a package object
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_completed_chunks(struct bpkg_obj* bpkg) { 
    struct bpkg_query qry = { 0 };
    if (bpkg == NULL || bpkg->chunks == NULL) {
        return qry;
    }
    // allocate memory for chunks 
    qry.hashes = (char **)malloc(bpkg->nchunks * HASH_LENGTH);
    if (qry.hashes == NULL) {
        return qry;
    }
    // path to keep track of completed chunks
    int path[LENGTH];
    // initialise the 
    for (size_t i = 0; i < bpkg->nchunks; i++) {
        path[i] = 0;
    }
    // read the file
    FILE *file = fopen(bpkg->filename, "rb");
    if (file == NULL) {
        //  Unable to open the data file
        return qry;
    }
    // compute the chunks that are completed and stores in path
    size_t completed_chunk = compute_completed_hashes(bpkg, file, &qry, path);
    // this will store the completed chunks
    qry.len = completed_chunk;
   // index is for the index of the hashes we return 
    size_t index = 0;
    // for each chunk check if it is completed, if it is then we add it to qry.hashes
    for (size_t i = 0; i < bpkg->nchunks; i++) {
        // check if the chunk at index i, is completed
        if (path[i] == 1) {
            qry.hashes[index] = strdup(bpkg->chunks[i]->hash);
            if (qry.hashes[index] == NULL) {
                // if allocation fails then we just free hashes
                for (size_t j = 0; j < index; j++) {
                    free(qry.hashes[j]);
                }
                free(qry.hashes);
                fclose(file);
                return (struct bpkg_query){ 0 };
            }
            index += 1;
        }
    }
    fclose(file);
    return qry;
}
  

/**
 * Gets the mininum of hashes to represented the current completion state
 * Example: If chunks representing start to mid have been completed but
 * 	mid to end have not been, then we will have (N_CHUNKS/2) + 1 hashes
 * 	outputted
 *
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */


struct bpkg_query bpkg_get_min_completed_hashes(struct bpkg_obj *bpkg) {
    struct bpkg_query qry = { 0 };
    // if the object is NULL
    if (bpkg == NULL || bpkg->chunks == NULL) {
        // invalid input
        return qry;
    }
    // open the file
    FILE *file = fopen(bpkg->filename, "rb");
    if (file == NULL) {
        // Unable to open the data file
        return qry;
    }
    qry.hashes = malloc(sizeof(char *) * bpkg->nhashes);
    if (qry.hashes == NULL) {
        fclose(file);
        // memory allocation failed
        return qry;
    }
    int path[LENGTH] = { 0 };
    // compute the completed hashes from chunks
    // path_index will store the total number of chunks that are complete
    size_t path_index = compute_completed_hashes(bpkg, file, &qry, path);
    fclose(file);
    // if the total chunks completed is equal to the nchunks, then we return the root of the tree
    if (path_index == bpkg->nchunks) {
        qry.hashes[0] = strdup(bpkg->hashes[0]);
        qry.len = 1;
    } else {
        // this keeps track of which nodes in the tree are completed
        int completed_status[LENGTH] = {0};
        // this is the start index of the first node on the last level of the tree
        int start_indx = bpkg->nchunks/2-1;
        int completed_parents = 0;
        /* we loop through all the chunks in pairs of 2, and if they are oth completed 
        then the parent will be completed */
        /* when the parent is cpmpleted we dont return the children, so we remove 
        the chunks from the completed in path */
        for (size_t j = 0; j < bpkg->nchunks; j+=2) {
            if ((path[j] == 1) && (path[j+1] == 1)) {
                completed_parents += 1;
                path[j] = 0;
                path[j+1] = 0;
                completed_status[start_indx] = 1;
                start_indx +=1;
            } else {
                start_indx += 1;
            }

        }
        qry.len = 0;
        /* if no nodes in the tree are cmpleted, we return all the chunks that 
            are completed*/
        if (completed_parents == 0) {
            for (int i = 0; i < bpkg->nchunks; i++) {
                if (path[i] == 1) {
                    qry.hashes[qry.len] = strdup(bpkg->chunks[i]->hash); 
                    qry.len++;
                }
            }
            return qry;
        } else {   
            /* if there are nodes in the tree that are completed and we also have 
                chunks that are completed, we return both*/         
            qry.len = 0;
            for (int i = 0; i < bpkg->nhashes; i++) {
                if (path[i] == 1) {
                    // if the node is completed, we add it to qry
                    qry.hashes[qry.len] = strdup(bpkg->chunks[i]->hash); 
                    qry.len++;
                }
            }
            for (size_t i = 0; i < bpkg->nhashes; i++) {
                if (completed_status[i] == 1) {
                    // if a chunk is completed, we add it to qry
                    qry.hashes[qry.len] = strdup(bpkg->hashes[i]); 
                    qry.len++;
                }
            }
            return qry;
        }     
    }
    qry.len = 1;
    return qry;
}


/**
 * Retrieves all chunk hashes given a certain an ancestor hash (or itself)
 * Example: If the root hash was given, all chunk hashes will be outputted
 * 	If the root's left child hash was given, all chunks corresponding to
 * 	the first half of the file will be outputted
 * 	If the root's right child hash was given, all chunks corresponding to
 * 	the second half of the file will be outputted
 * @param bpkg, constructed bpkg object
 * @return query_result, This structure will contain a list of hashes
 * 		and the number of hashes that have been retrieved
 */
struct bpkg_query bpkg_get_all_chunk_hashes_from_hash(struct bpkg_obj *bpkg, char *hash) {
    struct bpkg_query qry = { 0 };
    // check for invalid bpkg
    if (bpkg == NULL || bpkg->chunks == NULL || hash == NULL) {
        // Invalid input
        return qry;
    }
    /*  we check for all the hashes in the chunks fields to check if the given 
        hash matches with any of them*/
    struct chunk *startChunk = find_chunk_by_hash(bpkg, hash);
    /* we check if the hash is in hashes of bpkg, if its not then we store 
        hash_index as -1*/
    int hash_index = (startChunk == NULL) ? find_hash_index(bpkg, hash) : -1;
    // if the hash isnt found in either of chunks or hashes
    if (startChunk == NULL && hash_index == -1) {
        // Hash not found in chunks or hashes
        return qry;
    }
    qry.len = bpkg->nchunks;
    // allocate memory for the hashes
    qry.hashes = (char **)malloc(sizeof(char *) * qry.len);
    if (qry.hashes == NULL) {
        // Memory allocation failed
        return qry;
    }
    size_t count = 0;
    // if the hash is found in chunks
    if (startChunk != NULL) {
        for (uint32_t i = 0; i < bpkg->nchunks; i++) {
            struct chunk *currentChunk = bpkg->chunks[i];
            if (currentChunk->offset >= startChunk->offset &&
                currentChunk->offset + currentChunk->size <= 
                startChunk->offset + startChunk->size) {
                qry.hashes[count++] = strdup(currentChunk->hash);
            }
        }
    } else if (hash_index != -1) {
        // if the hash is found in hashes
        if (hash_index == 0) {
            // if its the root hash, then we return all the chunks
            collect_chunk_hashes(&qry, bpkg->chunks, 0, bpkg->nchunks, &count);
        } else {
            // otherwise we check where the node is located and its depth
            int depth = compute_depth(hash_index);
            // from the depth we can find the number of chunks we need to return
            int hashes_to_return = calculate_hashes_to_return(bpkg->nhashes, depth);
            int path[LENGTH];
            int path_length;
            // compute the path from root to node, this is for finding the start index
            compute_path_to_root(hash_index, path, &path_length);
            // we get the start index of the chunks we need to return
            int start_index = calculate_start_index(path, path_length, bpkg->nhashes);
            // we add all the hashes of chunks from the start index to the end index
            collect_chunk_hashes(&qry, bpkg->chunks, start_index, start_index + hashes_to_return, 
                                &count);
        }
    }
    qry.len = count;
    return qry;
}


/**
 * Deallocates the query result after it has been constructed from
 * the relevant queries above.
 */
void bpkg_query_destroy(struct bpkg_query* qry) {
    // deallocates memory for all hashes
    for (size_t i = 0; i < qry->len; i++) {
        free(qry->hashes[i]);
    }
    // free memory for hashes
    free(qry->hashes);
}


/**
 * Deallocates memory at the end of the program,
 * make sure it has been completely deallocated
 */
void bpkg_obj_destroy(struct bpkg_obj* obj) {
    if (obj == NULL) {
        // Nothing to deallocate
        return;
    }
    // deallocates memory for all hashes
    for (size_t i = 0; i < obj->nhashes; i++) {
        free(obj->hashes[i]);
    }
    free(obj->hashes);
    // deallocates memory for all chunks
    for (size_t i = 0; i < obj->nchunks; i++) {
        free(obj->chunks[i]->hash);
        free(obj->chunks[i]);
    }
    free(obj->chunks);
    // deallocates memory for the obj
    free(obj);

}