#include "request_list.h"



struct request_list *head = NULL;
struct request_list *curr = NULL;

struct request_list * create_list(char * target, EC_KEY * key, char * nonce) {
	struct request_list *ptr = (struct request_list*) malloc(sizeof(struct request_list));

	if(ptr == NULL) {
		puts("error while creating request list");
		return NULL;
	}
		
	ptr->target = malloc(strlen(target));
	ptr->target = target;
	ptr->key = malloc(sizeof(key));
	ptr->key = key;
	ptr->nonce = malloc(strlen(nonce));
	ptr->nonce = nonce;
	
	ptr->next = NULL;
	
	head = curr = ptr;


	return ptr;
}

struct request_list * add_to_list(char * target, EC_KEY * key, char * nonce) {
	if(head == NULL) {
		return (create_list(target, key, nonce));
	}

	struct request_list *ptr = (struct request_list*)malloc(sizeof(struct request_list));
	
	if(ptr == NULL) {
		puts("error while creating ptr");
		return NULL;
	}
	ptr->target = malloc(strlen(target));
	ptr->target = target;
	ptr->key = malloc(sizeof(key));
	ptr->key = key;
	ptr->nonce = malloc(strlen(nonce));
	ptr->nonce = nonce;
	ptr->next = NULL;

	curr->next = ptr;
	curr = ptr;

	return ptr;
}

struct request_list * search(char * target, struct request_list **prev) {
	struct request_list *ptr = head;
	struct request_list *tmp = NULL;
	bool found = false;

	while(ptr != NULL) {
		if(strcmp(target, ptr->target) == 0) {
			found = true;
			break;
		}
		else {
			tmp = ptr;
			ptr = ptr->next;
		}
	}
	if(found == true) {
		if(prev) {
			*prev = tmp;
		}
		return ptr;
	}
	else {
		return NULL;
	}
}

int delete_from_list(char * target) {
	struct request_list *prev = NULL;
	struct request_list *del = NULL;

	del = search(target, &prev);
	if(del == NULL) {
		return -1;
	}
	else {
		if(prev != NULL)
			prev->next = del->next;

		if(del == curr)
			curr = prev;
		else if(del == head)
			head = del->next;
	}
	free(del);
	del = NULL;
	
	return 0;
	
}


void print_list() {
	struct request_list *ptr = head;
	puts("----------");
	if(ptr == NULL) {
		puts("empty list");
	}
	else {
		while(ptr != NULL) {
			printf("target: %s\n", ptr->target);
			printf("nonce: %s\n", ptr->nonce);
			ptr = ptr->next;
		}
	}
	puts("----------");
}
