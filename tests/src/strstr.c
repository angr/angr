#include <string.h>

int main(void)
{
	char buf[] = "hello hi there";
	
	char * pch;
	
	pch = strstr(buf, "hi");

	puts(pch);

	return 0;
}
