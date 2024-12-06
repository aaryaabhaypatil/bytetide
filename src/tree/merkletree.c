#include "../../include/tree/merkletree.h"
#include "../../include/chk/pkgchk.h"
#include "../../include/crypt/sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


// function to create an instance of the merkle tree node
struct merkle_tree_node* create_merkle_tree_node(char* hash, int is_leaf) {
    struct merkle_tree_node* node = (struct merkle_tree_node*)malloc(sizeof(struct merkle_tree_node));
    node->left = NULL;
    node->right = NULL;
    node->is_leaf = is_leaf;
    strncpy(node->expected_hash, hash, SHA256_HEXLEN);
    memset(node->computed_hash, 0, SHA256_HEXLEN);
    return node;
}

// adds the node to the queue
void enqueue(struct Queue* q, struct merkle_tree_node* treeNode) {
    struct QueueNode* temp = (struct QueueNode*)malloc(sizeof(struct QueueNode));
    temp->treeNode = treeNode;
    temp->next = NULL;
    if (q->rear == NULL) {
        q->front = q->rear = temp;
        return;
    }
    q->rear->next = temp;
    q->rear = temp;
}

// removes a node from the queue
struct merkle_tree_node* dequeue(struct Queue* q) {
    if (q->front == NULL) return NULL;
    struct QueueNode* temp = q->front;
    q->front = q->front->next;
    if (q->front == NULL) q->rear = NULL;
    struct merkle_tree_node* treeNode = temp->treeNode;
    free(temp);
    return treeNode;
}

// checks if the queue is empty
bool isQueueEmpty(struct Queue* q) {
    return q->front == NULL;
}


// insert the values of hashes in the nodes of the tree in level order
struct merkle_tree_node* insertLevelOrder(struct bpkg_obj* obj) {
    if (obj->nhashes == 0) return NULL;
    // Creating a root and marking it as a leaf node
    struct merkle_tree_node* root = create_merkle_tree_node(obj->hashes[0], 1); 
    // queue to help with the level order insertion
    struct Queue q = {NULL, NULL};
    // add the root to the queue
    enqueue(&q, root);
    // now we start with the second hash
    int i = 1;
    // we continue till all are inserted
    while (i < obj->nhashes) {
        struct merkle_tree_node* temp = dequeue(&q);
        if (i < obj->nhashes) {
            temp->left = create_merkle_tree_node(obj->hashes[i++], 1);
            enqueue(&q, temp->left);
        }
        if (i < obj->nhashes) {
            temp->right = create_merkle_tree_node(obj->hashes[i++], 1);
            enqueue(&q, temp->right);
        }
    }
    return root;
}


void computeLeafHashes(struct merkle_tree_node* root, struct bpkg_obj* obj) {
    struct Queue q = {NULL, NULL};
    enqueue(&q, root);
    int chunk_index = 0;

    while (!isQueueEmpty(&q)) {
        struct merkle_tree_node* node = dequeue(&q);

        if (node->is_leaf) {
            struct chunk* chunk = obj->chunks[chunk_index++];
            struct sha256_compute_data cdata = { 0 };

            uint8_t hashout[SHA256_INT_SZ]= { 0 };
            char final_hash[65] = { 0 };
            sha256_compute_data_init(&cdata);
            // sha256_update(&cdata, bpkg->chunks[i]->size);
            sha256_finalize(&cdata, hashout);
            sha256_output_hex(&cdata, final_hash);
            strncpy(node->computed_hash, final_hash, SHA256_HEXLEN);
        }

        if (node->left != NULL) enqueue(&q, node->left);
        if (node->right != NULL) enqueue(&q, node->right);
    }
}
