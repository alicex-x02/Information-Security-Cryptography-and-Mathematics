#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <assert.h>
#include <time.h>
// 사용자 정의함수 구현
// 여기에서 자유롭게 문제 풀이를 위한 함수를 정의해서 사용하면 됨

// test 함수들
void inputMat(int* matrix[], int numRows, int numCols, int mod) {
	int i, j;
	for (i = 0; i < numRows; i++) {
		for (j = 0; j < numCols; j++) {
			matrix[i][j] = rand() % mod;
		}
	}
}
void printMat(int* matrix[], int numRows, int numCols) {
	int i, j;
	for (i = 0; i < numRows; i++) {
		for (j = 0; j < numCols; j++) {
			printf("%d\t", matrix[i][j]);
		}
		printf("\n");
	}
}
void matrixAdd(int* addMat[], int* matA[], int* matB[], int numRows, int numCols) {
	int i, j;
	for (i = 0; i < numRows; i++) {
		for (j = 0; j < numCols; j++) {
			addMat[i][j] = matA[i][j] + matB[i][j];
		}
	}
}
void matrixMul(int* mulMat[], int* matA[], int* matB[], int numRows, int numCols) {
	int i, j, k;
	for (i = 0; i < numRows; i++) {
		for (j = 0; j < numCols; j++) {
			for (k = 0; k < numRows; k++) {
				mulMat[i][j] += (matA[i][k] * matB[k][j]);
			}
		}
	}
}
void test1()
{
	int row = 0;
	int col = 0;
	int** matrixA = NULL, ** matrixB = NULL;
	int** addMat = NULL, ** mulMat = NULL;
	int i, j = 0;;

	srand(time(NULL));

	printf("행과 열을 입력하시오: ");
	scanf("%d%d", &row, &col);

	matrixA = (int**)calloc(row, sizeof(int*));
	assert(matrixA != NULL);

	matrixB = (int**)calloc(row, sizeof(int*));
	assert(matrixB != NULL);

	addMat = (int**)calloc(row, sizeof(int*));
	assert(addMat != NULL);

	mulMat = (int**)calloc(row, sizeof(int*));
	assert(mulMat != NULL);

	for (i = 0; i < row; i++) {
		matrixA[i] = (int*)calloc(col, sizeof(int));
		assert(matrixA[i] != NULL);
		matrixB[i] = (int*)calloc(col, sizeof(int));
		assert(matrixB[i] != NULL);
		addMat[i] = (int*)calloc(col, sizeof(int));
		assert(addMat[i] != NULL);
		mulMat[i] = (int*)calloc(col, sizeof(int));
		assert(mulMat[i] != NULL);
	}

	inputMat(matrixA, row, col, 16);
	inputMat(matrixB, row, col, 16);

	printf("[Matrix A]\n");
	printMat(matrixA, row, col);

	printf("[Matrix B]\n");
	printMat(matrixB, row, col);

	matrixAdd(addMat, matrixA, matrixB, row, col);
	matrixMul(mulMat, matrixA, matrixB, row, col);

	printf("[Matrix addition]\n");
	printMat(addMat, row, col);

	printf("[Matrix multiplication]\n");
	printMat(mulMat, row, col);

	for (i = 0; i < row; i++) {
		free(matrixA[i]);
		free(matrixB[i]);
		free(addMat[i]);
		free(mulMat[i]);
	}
}
LARGE_INTEGER Frequency;
LARGE_INTEGER BeginTime;
LARGE_INTEGER Endtime;
__int64 elapsed;
double duringtime;

void test2()
{
	int i;
	int* dataList = NULL;

	FILE* bfp = NULL;
	FILE* tfp = NULL;

	QueryPerformanceFrequency(&Frequency);

	dataList = (int*)calloc(10000, sizeof(int));

	for (i = 0; i < 10000; i++) {
		dataList[i] = i;
	}

	bfp = fopen("exec8_binary.dat", "wb");
	assert(bfp != NULL);

	tfp = fopen("exec8_text.text", "w");
	assert(tfp != NULL);

	QueryPerformanceCounter(&BeginTime);
	fwrite(dataList, sizeof(int), 10000, bfp);
	QueryPerformanceCounter(&Endtime);

	elapsed = Endtime.QuadPart - BeginTime.QuadPart; 
	duringtime = (double)elapsed / (double)Frequency.QuadPart;
	printf("elapsed time with binary file: %lf\n", duringtime);

	QueryPerformanceCounter(&BeginTime);
	for (i = 0; i < 10000; i++) {
		fprintf(tfp, "%d", dataList[i]);
	}
	QueryPerformanceCounter(&Endtime);

	elapsed = Endtime.QuadPart - BeginTime.QuadPart;
	duringtime = (double)elapsed / (double)Frequency.QuadPart;
	printf("elapsed time with text file: %lf\n", duringtime);

	if (bfp != NULL) {
		fclose(bfp);
	}
	if (tfp != NULL) {
		fclose(tfp);
	}
}
#pragma once
#define MAXSTRLEN 32
typedef struct _LISTNODE_ {
	char data[MAXSTRLEN];
	struct _LISTNODE_* link;
}listNode;

typedef struct _LINKEDLIST_H_ {
	listNode* head;
}linkedList_h;


linkedList_h* createLinkedList_h(void) {
	linkedList_h* L;
	L = (linkedList_h*)calloc(1, sizeof(linkedList_h));
	L->head = NULL;
	return L;
}

void printList(linkedList_h* L) {
	listNode* p;
	printf("L = (");
	p = L->head;
	while (p != NULL) {
		printf("%s", p->data);
		p = p->link;
		if (p != NULL)
			printf(", ");
	}
	printf(") \n");
}
void insertFirstNode(linkedList_h* L, char* x) {
	listNode* newNode;
	newNode = (listNode*)malloc(sizeof(listNode));
	strcpy(newNode->data, x);
	newNode->link = L->head;
	L->head = newNode;
}
void insertMiddleNode(linkedList_h* L, listNode* pre, char* x) {
	listNode* newNode;

	newNode = (listNode*)malloc(sizeof(listNode));
	strcpy(newNode->data, x);

	if (L->head == NULL) {
		newNode->link = NULL;
		L->head = newNode;
	}
	else if (pre == NULL) {
		newNode->link = NULL; 
		L->head = newNode; 
	}
	else {
		newNode->link = pre->link;
		pre->link = newNode;
	}
}
void insertLastNode(linkedList_h* L, char* x) {
	listNode* newNode;
	listNode* temp;
	newNode = (listNode*)malloc(sizeof(listNode));
	strcpy(newNode->data, x);
	newNode->link = NULL;
	if (L->head == NULL) {
		L->head = newNode;
		return;
	}
	temp = L->head;
	while (temp->link != NULL) temp = temp->link;
	temp->link = newNode;
}
listNode* searchNode(linkedList_h* L, char* x) {
	listNode* temp;
	temp = L->head;
	while (temp != NULL) {
		if (strcmp(temp->data, x) == 0)return temp;
		else temp = temp->link;
	}
	return temp;
}
void deleteNode(linkedList_h* L, listNode* p) {
	listNode* pre = NULL;
	listNode* cur = NULL;
	listNode* find = NULL;

	if (L->head == NULL || p == NULL) return;

	pre = cur = L->head;
	if (pre == p) {
		cur = pre->link;
		free(pre);
		L->head = cur;
		return;
	}

	cur = cur->link;
	while (cur != NULL) {
		if (cur == p) {
			find = cur;
			break;
		}
		pre = cur;
		cur = cur->link;
	}
	if (find != NULL) {
		pre->link = find->link;
		free(find);
	}
}
void freeLinkedList_h(linkedList_h* L) {
	listNode* p;

	if (L != NULL) {
		while (L->head != NULL) {
			p = L->head;
			L->head = L->head->link;
			free(p);
			p = NULL;
		}
		L->head = NULL;
	}
	else {
		fprintf(stderr, "error: NULL list\n");
		return;
	}
}
void orderedInsert(linkedList_h* L, char* x) {
	listNode* pre = NULL;
	listNode* cur = NULL;
	listNode* newNode = NULL;

	newNode = (listNode*)malloc(sizeof(listNode));
	strncpy(newNode->data, x, MAXSTRLEN);
	newNode->link = NULL;

	pre = cur = L->head;

	if (cur == NULL) {
		L->head = newNode;
		return;
	}
	else if (cur != NULL) 
	{
		if (strncmp(cur->data, x, MAXSTRLEN) > 0) 
		{
			newNode->link = cur;
			L->head = newNode;
			return;
		}
	}
		cur = cur->link;
		while (cur != NULL) {
			if (strncmp(cur->data, x, MAXSTRLEN) > 0) {
			break;
			}
			pre = cur;
			cur = cur->link;
		}
		newNode->link = pre->link;
		pre->link = newNode;

}
void test3()
{
	linkedList_h* L;
	linkedList_h* L2;
	linkedList_h* L3;
	listNode* p;

	L = createLinkedList_h();
	L2 = createLinkedList_h();
	L3 = createLinkedList_h();



	printf("\n(1) 리스트의 머리에 노드 삽입하기! \n");
	insertFirstNode(L, "apple");
	insertFirstNode(L, "banana");
	insertFirstNode(L, "cat");
	printList(L); 

	printf("\n(2) 리스트의 꼬리에 노드 삽입하기! \n");
	insertLastNode(L2, "apple");
	insertLastNode(L2, "banana"); 
	insertLastNode(L2, "cat");
	printList(L2);
	getchar();

	printf("\n(3) 리스트에서 노드 탐색하기! \n");
	p = searchNode(L, "banana");
	if (p == NULL) printf("찾는 데이터가 없습니다. \n");
	else printf("[%s]를 찾았습니다.\n", p->data);

	insertMiddleNode(L, p, "test");

	p = searchNode(L, "test");
	if (p == NULL) printf("찾는 데이터가 없습니다. \n");
	else printf("[%s]를 찾았습니다.\n", p->data);

	printf("\n(4) 리스트에서 중간에 노드 삽입하기! \n");
	insertMiddleNode(L, p, "zero");
	printList(L);

	printf("\n(5) 리스트에 정렬하여 노드 삽입하기! \n");
	orderedInsert(L3, "absolute");
	orderedInsert(L3, "affine");
	orderedInsert(L3, "attain");
	orderedInsert(L3, "blue");
	orderedInsert(L3, "friday");
	orderedInsert(L3, "test");
	printList(L3);

	printf("\n(6) 리스트에서 노드 탐색하기! \n");
	p = searchNode(L3, "absolute");
	deleteNode(L3, p);
	printList(L3); getchar();

	getchar();

	freeLinkedList_h(L);
	if (L != NULL) {
		free(L);
	}
	getchar();

}

int main()
{
	//test1();		// 동적메모리할당 3-3
	//test2();		// 파일입출력 7
	test3();		// 연결리스트 2
	return 0;
}

// EOF
