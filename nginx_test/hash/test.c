/*************************************************************************
	> File Name: test.c
	> Author: ma6174
	> Mail: ma6174@163.com 
	> Created Time: 2014年06月07日 13时24分20秒 CST
 ************************************************************************/

#include<stdio.h>

static char *test[3] = 
{"www.baidu.com", "www.baidu.com", "www.baidu.com"};
int main(void)
{
	//test[1][2] = 'W';
	printf("%p %p %p", test[0], test[1], "%p %p %p");
	return 0;
}
