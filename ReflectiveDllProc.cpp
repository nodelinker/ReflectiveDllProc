#include <windows.h>
#include <stdio.h>



#define SWAP32(x) ((UINT)((((UINT)(x) & 0xFF000000) >> 24) | \
	(((UINT)(x) & 0x00FF0000) >> 8) | \
	(((UINT)(x) & 0x0000FF00) << 8) | \
	(((UINT)(x) & 0x000000FF) << 24)))


char loader[] = "\x4D"
          "\x5A" 
          "\xE8\x00\x00\x00\x00" 
          "\x5B" 
          "\x52" 
          "\x45" 
          "\x55"  
          "\x89\xE5"  
          "\x81\xC3\x41\x41\x41\x41" 
          "\xFF\xD3" 
          "\x89\xC3" 
		  
		  "\x31\xff\x57\x57\x50\xff\xd0\x89\xec\x83\xc4\x04\xc3"
		  ;

PIMAGE_SECTION_HEADER ImageRVA2Section(PIMAGE_NT_HEADERS lpNtHdr, DWORD dwRVA);
PIMAGE_SECTION_HEADER ImageOffset2Section(PIMAGE_NT_HEADERS lpNtHdr,DWORD dwRO);
// calulates the Offset from a RVA
// Base    - base of the MMF
// dwRVA - the RVA to calculate
// returns 0 if an error occurred else the calculated Offset will be returned
DWORD RVA2Offset(PIMAGE_NT_HEADERS lpNtHdr, DWORD dwRVA)
{
	DWORD _offset;
	PIMAGE_SECTION_HEADER section;
	section=ImageRVA2Section(lpNtHdr, dwRVA);//ImageRvaToSection(plpNtHdr,Base,dwRVA);
	if(section==NULL)
	{
		return(0);
	}
	_offset=dwRVA+section->PointerToRawData-section->VirtualAddress;
	return(_offset);
}
//----------------------------------------------------------------
// calulates the RVA from a Offset
// Base    - base of the MMF
// dwRO - the Offset to calculate
// returns 0 if an error occurred else the calculated Offset will be returned
DWORD Offset2RVA(PIMAGE_NT_HEADERS lpNtHdr, DWORD dwRO)
{
	PIMAGE_SECTION_HEADER section;
	section=ImageOffset2Section(lpNtHdr, dwRO);
	if(section==NULL)
	{
		return(0);
	}
	return(dwRO+section->VirtualAddress-section->PointerToRawData);
}
//================================================================
//----------------------------------------------------------------
PIMAGE_SECTION_HEADER ImageRVA2Section(PIMAGE_NT_HEADERS lpNtHdr, DWORD dwRVA)
{
	int i;
	PIMAGE_SECTION_HEADER lpSecHdr = IMAGE_FIRST_SECTION(lpNtHdr);
	for(i=0;i<lpNtHdr->FileHeader.NumberOfSections;lpSecHdr++)
	{
		if((dwRVA>=lpSecHdr->VirtualAddress) && (dwRVA<=(lpSecHdr->VirtualAddress+lpSecHdr->SizeOfRawData)))
		{
			return ((PIMAGE_SECTION_HEADER)lpSecHdr);
		}
	}
	return(NULL);
}

//----------------------------------------------------------------
//The ImageOffset2Section function locates a Off Set address (RO) 
//within the image header of a file that is mapped as a file and
//returns a pointer to the section table entry for that virtual 
//address.
PIMAGE_SECTION_HEADER ImageOffset2Section(PIMAGE_NT_HEADERS lpNtHdr,DWORD dwRO)
{

	PIMAGE_SECTION_HEADER lpSecHdr = IMAGE_FIRST_SECTION(lpNtHdr);
	for(int i=0;i<lpNtHdr->FileHeader.NumberOfSections;lpSecHdr++)
	{
		if((dwRO>=lpSecHdr->PointerToRawData) && (dwRO<(lpSecHdr->PointerToRawData+lpSecHdr->SizeOfRawData)))
		{
			return ((PIMAGE_SECTION_HEADER)lpSecHdr);
		}
	}
	return(NULL);
}

int findReflectiveLoader(char * pImageBase){
	PIMAGE_DOS_HEADER lpDosHdr;
	PIMAGE_NT_HEADERS lpNtHdr;
	PIMAGE_SECTION_HEADER pSection, lpSecHdr;
	
	lpDosHdr = (PIMAGE_DOS_HEADER)pImageBase;
	if (lpDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("[-] DOS signature not found\n");
		return -1;
	}
	
	lpNtHdr = (PIMAGE_NT_HEADERS)((DWORD)pImageBase + lpDosHdr->e_lfanew);
	if (lpNtHdr->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("[-] NT signature not found\n");
	}

	lpSecHdr = IMAGE_FIRST_SECTION(lpNtHdr);
	
	while (true)
	{
		if (strncmp((char *)lpSecHdr->Name, ".text", 5) ==0)
		{
	
			break;
		}
		lpSecHdr++;
	}


	PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)pImageBase + RVA2Offset(lpNtHdr,lpNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	DWORD	iNumberOfFunctions	= pExport->NumberOfFunctions;
	DWORD	iNumberOfNames		= pExport->NumberOfNames;
	DWORD	*pAddressOfFunctions = (DWORD *)(pImageBase + RVA2Offset(lpNtHdr, pExport->AddressOfFunctions));
	DWORD	*pAddressOfNames	= (DWORD *)( pImageBase + RVA2Offset(lpNtHdr, pExport->AddressOfNames));
	
	
	UINT		i = 0;

	while (i < iNumberOfNames)
	{
		if (strstr((char *)(pImageBase + RVA2Offset(lpNtHdr, pAddressOfNames[i])), "ReflectiveLoader"))
		{
			DWORD dwFileOffset = RVA2Offset(lpNtHdr, (DWORD)pAddressOfFunctions[i]);
			printf("%08x \n", dwFileOffset-7);
			return dwFileOffset-7;

		}
		i++;
	}


	return 0;
}

int main(int argc, char **argv)
{
    HANDLE hFile, hFileMap;
	
	char 	*inBuf;
	int 	dwFileSize;
	BOOL	bResult;
	
	DWORD 	dwOldProtect;
	
    if(argc != 2){
        printf("Usage: %s [PEFile]\n", argv[0]);
        return -1;
    }
	
	hFile = CreateFile(argv[1], GENERIC_WRITE | GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == INVALID_HANDLE_VALUE){
        printf("[-] Cannot open %s\n", argv[1]);
        return -1;
    }
     
    dwFileSize = GetFileSize(hFile, 0);
    if(!dwFileSize){
        printf("[-] Could not get files size\n");
        CloseHandle(hFile);
        return -1;
    }
	
	inBuf = (char *)malloc(dwFileSize);
	while(true){
		DWORD nBytesRead;
		bResult = ReadFile(hFile, inBuf, dwFileSize, &nBytesRead, NULL);
		if(nBytesRead == 0)
			break;
	}
	
	if (! VirtualProtect(inBuf, dwFileSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)){
		printf("[-] Set Memory Page Execute error: %d\n", GetLastError());
		return -1;
	}
	
	
	DWORD dwLoaderOffset = findReflectiveLoader((char *)inBuf);

	for (int i = 0; i < sizeof(loader); i++)
	{
		if (memcmp((char *)(loader+i), "\x41\x41\x41\x41", 4) == 0)
		{
			*(DWORD *)(loader + i) = dwLoaderOffset;
			break;
		}
	}

	CopyMemory(inBuf, loader, sizeof(loader));

	__asm call [inBuf];

	return 0;
}