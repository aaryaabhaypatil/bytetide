#ifndef MERKLE_TREE_H
#define MERKLE_TREE_H

#include <stddef.h>
#include <stdbool.h>

#define SHA256_HEXLEN (64)

struct merkle_tree_node {
    struct merkle_tree_node* left;
    struct merkle_tree_node* right;
    int is_leaf;
    char expected_hash[SHA256_HEXLEN];
    char computed_hash[SHA256_HEXLEN];
};


struct merkle_tree {
    struct merkle_tree_node* root;
    size_t n_nodes;
};

struct QueueNode {
    struct merkle_tree_node* treeNode;
    struct QueueNode* next;
};

struct Queue {
    struct QueueNode* front;
    struct QueueNode* rear;
};

struct merkle_tree_node* create_merkle_tree_node(char* hash, int is_leaf);
void enqueue(struct Queue* q, struct merkle_tree_node* treeNode);
struct merkle_tree_node* dequeue(struct Queue* q);
bool isQueueEmpty(struct Queue* q);
struct merkle_tree_node* insertLevelOrder(struct bpkg_obj* obj);
void computeLeafHashes(struct merkle_tree_node* root, struct bpkg_obj* obj);

#endif
