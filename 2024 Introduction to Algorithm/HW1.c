#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>

// 사용자 정의함수 구현
// 여기에서 자유롭게 문제 풀이를 위한 함수를 정의해서 사용하면 됨

// test 함수들
void test2()
{
	char word[100] = { 0, };
	int i = 0;
	printf("[임의의 n 바이트 문자열을 입력하세요]: ");
	//scanf("%s", &word);
	fgets(word, BUFSIZ, stdin);
	printf("\n입력받은 문자열 : %s\n", word);

	while (word[i]) {
		if (word[i] >= 'A' && word[i] <= 'Z')
			word[i] += 32;
		else if (word[i] >= 'a' && word[i] <= 'z')
			word[i] -= 32;
		i++;
	}

	printf("뒤바뀐 문자열\t: %s", word);


}

void test3()
{
	int arr[7][20] = { 0, };
	int i = 0;
	int j = 0;
	int k = 0;
	int a = 0;
	int b = 0;

	for (j = 1; j <= 20; j++) {
		arr[0][j - 1] = j;
	}
	for (int i = 1; i < 7; i++) {
		for (int j = 1; j <= 20; j++) {
			for (int k = 0; k < j; k++) {
				arr[i][j - 1] += arr[i - 1][k];
			}
		}
	}
	printf("[양의 정수 i, j를 입력하세요]: ");
	scanf("%d%d", &a, &b);
	printf("현재 %d층 %d호 에는 %d 명의 학생이 있습니다.", a, b, arr[a][b - 1]);
}
void test5() {
	int numArr[5] = { 11, 22, 33, 44, 55 };
	int* numPtrA;
	void* ptr;

	numPtrA = &numArr[2];
	ptr = numArr;

	printf("%d\n", *(numPtrA + 2));
	printf("%d\n", *((int*)ptr + 1));

}

int main()
{
	//test2();		// 2번 문제
	//test3();		// 3번 문제
	test5();		// 5번 문제
	return 0;
}

// EOF
