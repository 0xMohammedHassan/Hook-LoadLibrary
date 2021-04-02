#include <Windows.h>

#include <iostream>

using namespace std;


int main() {


	while(true)
	{
	cout << "Will load our library after 5 seconds ..." << endl;
	

	HMODULE mod = LoadLibraryA("lll.dll");

	if (mod == NULL) {

		cout << "Cant load the library ! " << GetLastError() << endl;
	//	getchar();

	}
	else{
	cout << " The library has been loaded successfully " << endl;
	getchar();
	}
	Sleep(5000);
	}
	getchar();
}