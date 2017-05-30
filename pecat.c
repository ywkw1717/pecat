#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#define IMAGE_DOS_SIGNATURE                0x5A4D     // MZ
#define IMAGE_NT_SIGNATURE                 0x00004550 // PE00
#define IMAGE_FILE_DLL                     0x200
#define IMAGE_FILE_MACHINE_I386            0x014c
#define IMAGE_FILE_MACHINE_AMD64           0x8664
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC      0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC      0x20b

#define IMAGE_SIZEOF_FILE_HEADER           20
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES   16
#define IMAGE_SIZEOF_SHORT_NAME            8

typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef uint32_t DWORD;
typedef uint64_t ULONGLONG;

typedef struct _IMAGE_DOS_HEADER {    // DOS .EXE header
  WORD   e_magic;                     // Magic number
  WORD   e_cblp;                      // Bytes on last page of file
  WORD   e_cp;                        // Pages in file
  WORD   e_crlc;                      // Relocations
  WORD   e_cparhdr;                   // Size of header in paragraphs
  WORD   e_minalloc;                  // Minimum extra paragraphs needed
  WORD   e_maxalloc;                  // Maximum extra paragraphs needed
  WORD   e_ss;                        // Initial (relative) SS value
  WORD   e_sp;                        // Initial SP value
  WORD   e_csum;                      // Checksum
  WORD   e_ip;                        // Initial IP value
  WORD   e_cs;                        // Initial (relative) CS value
  WORD   e_lfarlc;                    // File address of relocation table
  WORD   e_ovno;                      // Overlay number
  WORD   e_res[4];                    // Reserved words
  WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
  WORD   e_oeminfo;                   // OEM information; e_oemid specific
  WORD   e_res2[10];                  // Reserved words
  DWORD  e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
  WORD    Machine;
  WORD    NumberOfSections;
  DWORD   TimeDateStamp;
  DWORD   PointerToSymbolTable;
  DWORD   NumberOfSymbols;
  WORD    SizeOfOptionalHeader;
  WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
  WORD    Magic; // 0x20b
  BYTE    MajorLinkerVersion;
  BYTE    MinorLinkerVersion;
  DWORD   SizeOfCode;
  DWORD   SizeOfInitializedData;
  DWORD   SizeOfUninitializedData;
  DWORD   AddressOfEntryPoint;
  DWORD   BaseOfCode;
  DWORD   BaseOfData;
  DWORD   ImageBase;
  DWORD   SectionAlignment;
  DWORD   FileAlignment;
  WORD    MajorOperatingSystemVersion;
  WORD    MinorOperatingSystemVersion;
  WORD    MajorImageVersion;
  WORD    MinorImageVersion;
  WORD    MajorSubsystemVersion;
  WORD    MinorSubsystemVersion;
  DWORD   Win32VersionValue;
  DWORD   SizeOfImage;
  DWORD   SizeOfHeaders;
  DWORD   CheckSum;
  WORD    Subsystem;
  WORD    DllCharacteristics;
  DWORD   SizeOfStackReserve;
  DWORD   SizeOfStackCommit;
  DWORD   SizeOfHeapReserve;
  DWORD   SizeOfHeapCommit;
  DWORD   LoaderFlags;
  WORD   NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD  Magic; // 0x20b
  BYTE MajorLinkerVersion;
  BYTE MinorLinkerVersion;
  DWORD SizeOfCode;
  DWORD SizeOfInitializedData;
  DWORD SizeOfUninitializedData;
  DWORD AddressOfEntryPoint;
  DWORD BaseOfCode;
  ULONGLONG ImageBase;
  DWORD SectionAlignment;
  DWORD FileAlignment;
  WORD MajorOperatingSystemVersion;
  WORD MinorOperatingSystemVersion;
  WORD MajorImageVersion;
  WORD MinorImageVersion;
  WORD MajorSubsystemVersion;
  WORD MinorSubsystemVersion;
  DWORD Win32VersionValue;
  DWORD SizeOfImage;
  DWORD SizeOfHeaders;
  DWORD CheckSum;
  WORD Subsystem;
  WORD DllCharacteristics;
  ULONGLONG SizeOfStackReserve;
  ULONGLONG SizeOfStackCommit;
  ULONGLONG SizeOfHeapReserve;
  ULONGLONG SizeOfHeapCommit;
  DWORD LoaderFlags;
  DWORD NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS {
  DWORD Signature;
  // Do not use in this program.
  /* IMAGE_FILE_HEADER FileHeader; */
  /* IMAGE_OPTIONAL_HEADER32 OptionalHeader; */
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER,*PIMAGE_SECTION_HEADER;

typedef struct IMAGE_COR20_HEADER {
  DWORD                   cb;
  WORD                    MajorRuntimeVersion;
  WORD                    MinorRuntimeVersion;
  // Symbol table and startup information
  IMAGE_DATA_DIRECTORY    MetaData;
  DWORD                   Flags;
  DWORD                   EntryPointToken;
  // Binding information
  IMAGE_DATA_DIRECTORY    Resources;
  IMAGE_DATA_DIRECTORY    StrongNameSignature;
  // Regular fixup and binding information
  IMAGE_DATA_DIRECTORY    CodeManagerTable;
  IMAGE_DATA_DIRECTORY    VTableFixups;
  IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;

  IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
} IMAGE_COR20_HEADER;

typedef struct RESOURCE_MANAGER_HEADER {
  DWORD   Size;
  DWORD   Magic; // 0xBEEFCACE
  DWORD   HeaderVersion;
  DWORD   NumBytesToSkip;
  BYTE    *String;
} RESOURCE_MANAGER_HEADER;

typedef struct RUNTIME_RESOURCE_READER_HEADER {
  DWORD   Version; // 1 or 2
  DWORD   NumberOfResources;
  DWORD   NumberOfType;
  BYTE    PAD[7]; // "PAD" bytes to align the next data to 8n bytes
  DWORD   *HashValues; // Hash values for eaxh resource name
  DWORD   *VirtualOffset; // Virtual offset of each resource name
  DWORD   AbsoluteLocation; // Absolute location of Data section
} RUNTIME_RESOURCE_READER_HEADER;

typedef struct RUNTIME_RESOURCE_READER_NAME_SECTION {
  BYTE    StringLength;
  WORD    *Name;
  DWORD   VirtualOffset;
} RUNTIME_RESOURCE_READER_NAME_SECTION;

typedef struct RUNTIME_RESOURCE_READER_DATA_SECTION {
  BYTE    Top;
  BYTE    Size;
  BYTE    *Data;
} RUNTIME_RESOURCE_READER_DATA_SECTION;

typedef struct METADATA_HEADER {
  DWORD   Signature; // 0x424A5342(BJSB)
  WORD    MajorVersion;
  WORD    MinorVersion;
  DWORD   ExtraDataOffset;
  DWORD   VersionStringLength;
  BYTE    VersionString[];
} METADATA_HEADER;

IMAGE_DOS_HEADER dosHeader;
IMAGE_NT_HEADERS ntHeader;
IMAGE_FILE_HEADER fileHeader;
IMAGE_SECTION_HEADER sectionHeader;
IMAGE_COR20_HEADER clrHeader;
RESOURCE_MANAGER_HEADER resourceManagerHeader;
RUNTIME_RESOURCE_READER_HEADER runtimeResourceHeader;
RUNTIME_RESOURCE_READER_NAME_SECTION *nameSection;
RUNTIME_RESOURCE_READER_DATA_SECTION *dataSection;
METADATA_HEADER metadataHeader;
DWORD clrHeaderVirtualAddress;
DWORD clrHeaderSize;
DWORD clrHeaderOffset;
DWORD textSectionVirtualAddress;
DWORD textSectionSizeOfRawData;
DWORD textSectionPointerToRawData;
DWORD resourceOffset;

void getDosheader(FILE *fp){
  int i;

  fread(&dosHeader, sizeof(unsigned char), 64, fp);

  if(dosHeader.e_magic != IMAGE_DOS_SIGNATURE){
    printf("Failed.\nMZ Header is invalid.\n");
    exit(1);
  }

  printf("\n----DOS HEADER----\n");
  printf("e_magic:    %02X\n", dosHeader.e_magic);
  printf("e_clip:     %02X\n", dosHeader.e_cblp);
  printf("e_cp:       %02X\n", dosHeader.e_cp);
  printf("e_crlc:     %02X\n", dosHeader.e_crlc);
  printf("e_cparhdr:  %02X\n", dosHeader.e_cparhdr);
  printf("e_minalloc: %02X\n", dosHeader.e_minalloc);
  printf("e_maxalloc: %02X\n", dosHeader.e_maxalloc);
  printf("e_ss:       %02X\n", dosHeader.e_ss);
  printf("e_sp:       %02X\n", dosHeader.e_sp);
  printf("e_csum:     %02X\n", dosHeader.e_csum);
  printf("e_ip:       %02X\n", dosHeader.e_ip);
  printf("e_cs:       %02X\n", dosHeader.e_cs);
  printf("e_lfarlc:   %02X\n", dosHeader.e_lfarlc);
  printf("e_ovno:     %02X\n", dosHeader.e_ovno);
  printf("e_res[4]:   ");

  for(i = 0; i < 4; i++){
    printf("%02X ", dosHeader.e_res[i]);
  }

  printf("\n");
  printf("e_oemid:    %02X\n", dosHeader.e_oemid);
  printf("e_oeminfo:  %02X\n", dosHeader.e_oeminfo);
  printf("e_res2[10]: ");

  for(i = 0; i < 10; i++){
    printf("%02X ", dosHeader.e_res2[i]);
  }

  printf("\n");

  printf("e_lfanew:   %02X\n", dosHeader.e_lfanew);

  fseek(fp, dosHeader.e_lfanew, SEEK_SET); // preparation of ntHeader
}

void getNtHeader(FILE *fp){
  fread(&ntHeader, sizeof(unsigned char), 4, fp);

  printf("\n----NT HEADER----\n");

  if(ntHeader.Signature != IMAGE_NT_SIGNATURE){
    printf("Failed.\nNT Header is invalid.\n");
    exit(1);
  }

  printf("Signature:  %02X\n", ntHeader.Signature);
}

void getFileHeader(FILE *fp){
  fread(&fileHeader, sizeof(unsigned char), 20, fp);

  printf("\n----FILE HEADER----\n");
  printf("Machine:              %02X\n", fileHeader.Machine);
  printf("NumberOfSections:     %02X\n", fileHeader.NumberOfSections);
  printf("TimeDateStamp:        %02X\n", fileHeader.TimeDateStamp);
  printf("PointerToSymbolTable: %02X\n", fileHeader.PointerToSymbolTable);
  printf("NumberOfSymbols:      %02X\n", fileHeader.NumberOfSymbols);
  printf("SizeOfOptionalHeader: %02X\n", fileHeader.SizeOfOptionalHeader);
  printf("Characteristics:      %02X\n", fileHeader.Characteristics);
}

void getOptionalHeader(FILE *fp){
  int i;

  if(fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64){
    IMAGE_OPTIONAL_HEADER64 optionalheader;

    fread(&optionalheader, sizeof(unsigned char), fileHeader.SizeOfOptionalHeader, fp);

    printf("\n----OPTIONAL HEADER----\n");
    printf("Magic:                       %02X\n", optionalheader.Magic);
    printf("MajorLinkerVersion:          %02X\n", optionalheader.MajorLinkerVersion);
    printf("MinorLinkerVersion:          %02X\n", optionalheader.MinorLinkerVersion);
    printf("SizeOfCode:                  %02X\n", optionalheader.SizeOfCode);
    printf("SizeOfInitializedData:       %02X\n", optionalheader.SizeOfInitializedData);
    printf("SizeOfUninitializedData:     %02X\n", optionalheader.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:         %02X\n", optionalheader.AddressOfEntryPoint);
    printf("BaseOfCode:                  %02X\n", optionalheader.BaseOfCode);
    printf("ImageBase:                   %02lX\n", optionalheader.ImageBase);
    printf("SectionAlignment:            %02X\n", optionalheader.SectionAlignment);
    printf("FileAlignment:               %02X\n", optionalheader.FileAlignment);
    printf("MajorOperatingSystemVersion: %02X\n", optionalheader.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %02X\n", optionalheader.MinorOperatingSystemVersion);
    printf("MajorImageVersion:           %02X\n", optionalheader.MajorImageVersion);
    printf("MinorImageVersion:           %02X\n", optionalheader.MinorImageVersion);
    printf("MajorSubsystemVersion:       %02X\n", optionalheader.MajorSubsystemVersion);
    printf("MinorSubsystemVersion:       %02X\n", optionalheader.MinorSubsystemVersion);
    printf("Win32VersionValue:           %02X\n", optionalheader.Win32VersionValue);
    printf("SizeOfImage:                 %02X\n", optionalheader.SizeOfImage);
    printf("SizeOfHeaders:               %02X\n", optionalheader.SizeOfHeaders);
    printf("CheckSum:                    %02X\n", optionalheader.CheckSum);
    printf("Subsystem:                   %02X\n", optionalheader.Subsystem);
    printf("DllCharacteristics:          %02X\n", optionalheader.DllCharacteristics);
    printf("SizeOfStackReserve:          %02lX\n", optionalheader.SizeOfStackReserve);
    printf("SizeOfStackCommit:           %02lX\n", optionalheader.SizeOfStackCommit);
    printf("SizeOfHeapReserve:           %02lX\n", optionalheader.SizeOfHeapReserve);
    printf("SizeOfHeapCommit:            %02lX\n", optionalheader.SizeOfHeapCommit);
    printf("LoaderFlags:                 %02X\n", optionalheader.LoaderFlags);
    printf("NumberOfRvaAndSizes:         %02X\n", optionalheader.NumberOfRvaAndSizes);
    printf("\n----IMAGE_DATA_DIRECTORY----\n");

    for(i = 0; i < 16; i++){
      printf("VirtualAddress: %02X\n", optionalheader.DataDirectory[i].VirtualAddress);
      printf("Size:           %02X\n\n", optionalheader.DataDirectory[i].Size);
    }

    clrHeaderVirtualAddress = optionalheader.DataDirectory[14].VirtualAddress;
    clrHeaderSize = optionalheader.DataDirectory[14].Size;
  } else if(fileHeader.Machine == IMAGE_FILE_MACHINE_I386){
    IMAGE_OPTIONAL_HEADER32 optionalheader;

    fread(&optionalheader, sizeof(unsigned char), fileHeader.SizeOfOptionalHeader, fp);

    printf("\n----OPTIONAL HEADER----\n");
    printf("Magic:                       %02X\n", optionalheader.Magic);
    printf("MajorLinkerVersion:          %02X\n", optionalheader.MajorLinkerVersion);
    printf("MinorLinkerVersion:          %02X\n", optionalheader.MinorLinkerVersion);
    printf("SizeOfCode:                  %02X\n", optionalheader.SizeOfCode);
    printf("SizeOfInitializedData:       %02X\n", optionalheader.SizeOfInitializedData);
    printf("SizeOfUninitializedData:     %02X\n", optionalheader.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:         %02X\n", optionalheader.AddressOfEntryPoint);
    printf("BaseOfCode:                  %02X\n", optionalheader.BaseOfCode);
    printf("BaseOfData:                  %02X\n", optionalheader.BaseOfData);
    printf("ImageBase:                   %02X\n", optionalheader.ImageBase);
    printf("SectionAlignment:            %02X\n", optionalheader.SectionAlignment);
    printf("FileAlignment:               %02X\n", optionalheader.FileAlignment);
    printf("MajorOperatingSystemVersion: %02X\n", optionalheader.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %02X\n", optionalheader.MinorOperatingSystemVersion);
    printf("MajorImageVersion:           %02X\n", optionalheader.MajorImageVersion);
    printf("MinorImageVersion:           %02X\n", optionalheader.MinorImageVersion);
    printf("MajorSubsystemVersion:       %02X\n", optionalheader.MajorSubsystemVersion);
    printf("MinorSubsystemVersion:       %02X\n", optionalheader.MinorSubsystemVersion);
    printf("Win32VersionValue:           %02X\n", optionalheader.Win32VersionValue);
    printf("SizeOfImage:                 %02X\n", optionalheader.SizeOfImage);
    printf("SizeOfHeaders:               %02X\n", optionalheader.SizeOfHeaders);
    printf("CheckSum:                    %02X\n", optionalheader.CheckSum);
    printf("Subsystem:                   %02X\n", optionalheader.Subsystem);
    printf("DllCharacteristics:          %02X\n", optionalheader.DllCharacteristics);
    printf("SizeOfStackReserve:          %02X\n", optionalheader.SizeOfStackReserve);
    printf("SizeOfStackCommit:           %02X\n", optionalheader.SizeOfStackCommit);
    printf("SizeOfHeapReserve:           %02X\n", optionalheader.SizeOfHeapReserve);
    printf("SizeOfHeapCommit:            %02X\n", optionalheader.SizeOfHeapCommit);
    printf("LoaderFlags:                 %02X\n", optionalheader.LoaderFlags);
    printf("NumberOfRvaAndSizes:         %02X\n", optionalheader.NumberOfRvaAndSizes);
    printf("\n----IMAGE_DATA_DIRECTORY----\n");

    for(i = 0; i < 16; i++){
      printf("VirtualAddress: %02X\n", optionalheader.DataDirectory[i].VirtualAddress);
      printf("Size:           %02X\n\n", optionalheader.DataDirectory[i].Size);
    }

    clrHeaderVirtualAddress = optionalheader.DataDirectory[14].VirtualAddress;
    clrHeaderSize = optionalheader.DataDirectory[14].Size;
  } else{
    printf("Failed.\nFile Header is invalid.\n");
    exit(1);
  }
}

void getSectionHeader(FILE *fp){
  int i, flag = 0;

  printf("\n----SECTION HEADER----\n");

  for(i = 0; i < fileHeader.NumberOfSections; i++){
    fread(&sectionHeader, sizeof(unsigned char), 40, fp);

    if(!strcmp((const char*)sectionHeader.Name, ".text")){
      clrHeaderOffset = clrHeaderVirtualAddress - sectionHeader.VirtualAddress;
      textSectionVirtualAddress = sectionHeader.VirtualAddress;
      textSectionSizeOfRawData = sectionHeader.SizeOfRawData;
      textSectionPointerToRawData = sectionHeader.PointerToRawData;
      flag = 1;
    }

    printf("[%d]\n", i + 1);
    printf("Name:                 %s\n", sectionHeader.Name);
    printf("PhysicalAddress:      %02X\n", sectionHeader.Misc.PhysicalAddress);
    printf("VirtualSize:          %02X\n", sectionHeader.Misc.VirtualSize);
    printf("VirtualAddress:       %02X\n", sectionHeader.VirtualAddress);
    printf("SizeOfRawData:        %02X\n", sectionHeader.SizeOfRawData);
    printf("PointerToRawData:     %02X\n", sectionHeader.PointerToRawData);
    printf("PointerToRelocations: %02X\n", sectionHeader.PointerToRelocations);
    printf("PointerToLinenumbers: %02X\n", sectionHeader.PointerToLinenumbers);
    printf("NumberOfRelocations:  %02X\n", sectionHeader.NumberOfRelocations);
    printf("NumberOfLinenumbers:  %02X\n\n", sectionHeader.NumberOfLinenumbers);
  }

  // text section check
  if(!flag){
    printf("Failed.\ntext section is not found.\n");
    exit(1);
  }
}

void getClrHeader(FILE *fp){
  fseek(fp, textSectionPointerToRawData + clrHeaderOffset, SEEK_SET); // preparation of clrHeader
  fread(&clrHeader, sizeof(unsigned char), clrHeaderSize, fp);

  printf("\n----CLR HEADER----\n");

  // CLR Header check
  if(sizeof(clrHeader) != clrHeader.cb){
    printf("Failed.\nCLR Header is invalid or does not exit.\n");
    exit(1);
  }

  printf("cb:                      %02X\n", clrHeader.cb);
  printf("MajorRuntimeVersion:     %02X\n", clrHeader.MajorRuntimeVersion);
  printf("MinorRuntimeVersion:     %02X\n", clrHeader.MinorRuntimeVersion);
  printf("MetaData:                VirtualAddress: %02X , Size: %02X\n", clrHeader.MetaData.VirtualAddress, clrHeader.MetaData.Size);
  printf("Flags:                   %02X\n", clrHeader.Flags);
  printf("EntryPointToken:         %02X\n", clrHeader.EntryPointToken);
  printf("Resources:               VirtualAddress: %02X , Size: %02X\n", clrHeader.Resources.VirtualAddress, clrHeader.Resources.Size);
  printf("StrongNameSignature:     VirtualAddress: %02X , Size: %02X\n", clrHeader.StrongNameSignature.VirtualAddress, clrHeader.StrongNameSignature.Size);
  printf("CodeManagerTable:        VirtualAddress: %02X , Size: %02X\n", clrHeader.CodeManagerTable.VirtualAddress, clrHeader.CodeManagerTable.Size);
  printf("VTableFixups:            VirtualAddress: %02X , Size: %02X\n", clrHeader.VTableFixups.VirtualAddress, clrHeader.VTableFixups.Size);
  printf("ExportAddressTableJumps: VirtualAddress: %02X , Size: %02X\n", clrHeader.ExportAddressTableJumps.VirtualAddress, clrHeader.ExportAddressTableJumps.Size);
  printf("ManagedNativeHeader:     VirtualAddress: %02X , Size: %02X\n", clrHeader.ManagedNativeHeader.VirtualAddress, clrHeader.ManagedNativeHeader.Size);
}

void getResourceManagerHeader(FILE *fp){
  int i;

  if(clrHeader.Resources.Size != 0x0){
    resourceOffset = clrHeader.Resources.VirtualAddress - textSectionVirtualAddress;
  } else{
    printf("Failed.\nResource Header is not found.\n");
    exit(1);
  }

  printf("\n----Resource Manager Header----\n");
  fseek(fp, textSectionPointerToRawData + resourceOffset, SEEK_SET);
  fread(&resourceManagerHeader, sizeof(unsigned char), 16, fp);;

  if(resourceManagerHeader.Magic != 0xBEEFCACE){
    printf("Failed.\nSignature 0xBEEFCACE is not found.\nResource Manager Header is invalid or does not exist.\n");
    exit(1);
  }
  printf("Magic:          %02X\n", resourceManagerHeader.Magic);
  printf("HeaderVersion:  %02X\n", resourceManagerHeader.HeaderVersion);
  printf("NumBytesToSkip: %02X\n", resourceManagerHeader.NumBytesToSkip);

  resourceManagerHeader.String = (unsigned char*)malloc(sizeof(unsigned char) * resourceManagerHeader.NumBytesToSkip);
  fread(resourceManagerHeader.String, sizeof(unsigned char), resourceManagerHeader.NumBytesToSkip, fp);

  printf("String:         ");

  for(i = 0; i < resourceManagerHeader.NumBytesToSkip; i++){
    printf("%c", resourceManagerHeader.String[i]);
  }
  printf("\n");

  // free
  free(resourceManagerHeader.String);
}

void getRuntimeResourceHeader(FILE *fp){
  int i;

  printf("\n----Runtime Resource Reader Header----\n");
  fread(&runtimeResourceHeader, sizeof(unsigned char), 19, fp); // to PAD

  // input
  runtimeResourceHeader.HashValues = (DWORD*)malloc(sizeof(DWORD) * runtimeResourceHeader.NumberOfResources);
  for(i = 0; i < runtimeResourceHeader.NumberOfResources; i++){
    fread((runtimeResourceHeader.HashValues+ i), sizeof(unsigned char), 4, fp);
  }

  runtimeResourceHeader.VirtualOffset = (DWORD*)malloc(sizeof(DWORD) * runtimeResourceHeader.NumberOfResources);
  for(i = 0; i < runtimeResourceHeader.NumberOfResources; i++){
    fread((runtimeResourceHeader.VirtualOffset + i), sizeof(unsigned char), 4, fp);
  }

  fread(&runtimeResourceHeader.AbsoluteLocation, sizeof(unsigned char), 4, fp); // AbsoluteLocation

  // output
  printf("Version:           %02X\n", runtimeResourceHeader.Version);
  printf("NumberOfResources: %02X\n", runtimeResourceHeader.NumberOfResources);
  printf("NumberOfType:      %02X\n", runtimeResourceHeader.NumberOfType);
  printf("Padding:           ");

  for(i = 0; i < 7; i++){
    printf("%c", runtimeResourceHeader.PAD[i]);
  }

  printf("\n\n");

  for(i = 0; i < runtimeResourceHeader.NumberOfResources; i++){
    printf("HashValues:       %02X\n", *(runtimeResourceHeader.HashValues + i));
    printf("VirtualOffset:    %02X\n", *(runtimeResourceHeader.VirtualOffset + i));
    printf("\n");
  }
  printf("AbsoluteLocation: %02X\n", runtimeResourceHeader.AbsoluteLocation);

  // free
  free(runtimeResourceHeader.HashValues);
  free(runtimeResourceHeader.VirtualOffset);
}

void getRuntimeResourceNameAndDataSection(FILE *fp){
  int i, j, dif;
  BYTE tmp;

  printf("\n\n----String Resource----\n");

  nameSection = (RUNTIME_RESOURCE_READER_NAME_SECTION*)malloc(sizeof(RUNTIME_RESOURCE_READER_NAME_SECTION) * runtimeResourceHeader.NumberOfResources);
  dataSection = (RUNTIME_RESOURCE_READER_DATA_SECTION*)malloc(sizeof(RUNTIME_RESOURCE_READER_DATA_SECTION) * runtimeResourceHeader.NumberOfResources);

  // Name Section input
  for(i = 0; i < runtimeResourceHeader.NumberOfResources; i++){
    fread(&(nameSection + i)->StringLength, sizeof(unsigned char), 1, fp);

    // up to 0x80
    if((nameSection + i)->StringLength >= 0x80){
      fread(&tmp, sizeof(unsigned char), 1, fp);

      dif = 0x80 * (tmp - 1);

      (nameSection + i)->Name = (WORD*)malloc(sizeof(WORD) * ((nameSection + i)->StringLength + dif)/2);
      fread((nameSection + i)->Name, sizeof(WORD), ((nameSection + i)->StringLength + dif)/2, fp);
      fread(&(nameSection + i)->VirtualOffset, sizeof(unsigned char), 4, fp);
    } else{
      (nameSection + i)->Name = (WORD*)malloc(sizeof(WORD) * ((nameSection + i)->StringLength)/2);
      fread((nameSection + i)->Name, sizeof(WORD), ((nameSection + i)->StringLength)/2, fp);
      fread(&(nameSection + i)->VirtualOffset, sizeof(unsigned char), 4, fp);
    }
  }

  // Data Section input
  for(i = 0; i < runtimeResourceHeader.NumberOfResources; i++){
    fread((dataSection + i), sizeof(unsigned char), 2, fp);

    // up to 0x80
    if((dataSection + i)->Size >= 0x80){
      fread(&tmp, sizeof(unsigned char), 1, fp);

      dif = 0x80 * (tmp - 1);

      (dataSection + i)->Data = (unsigned char*)malloc(sizeof(unsigned char) * ((dataSection + i)->Size + dif));
      fread((dataSection + i)->Data, sizeof(unsigned char), ((dataSection + i)->Size + dif), fp);
    } else{
      (dataSection + i)->Data = (unsigned char*)malloc(sizeof(unsigned char) * ((dataSection + i)->Size));
      fread((dataSection + i)->Data, sizeof(unsigned char), ((dataSection + i)->Size), fp);
    }
  }

  fseek(fp, 1, SEEK_CUR); // NULL String

  // output
  for(i = 0; i < runtimeResourceHeader.NumberOfResources; i++){
    printf("[%d]\n", i + 1);
    printf("Name:  ");
    for(j = 0; j < ((nameSection + i)->StringLength)/2; j++){
      printf("%c", (nameSection + i)->Name[j]);
    }
    printf("\n");
    printf("Value: ");
    for(j = 0; j < (dataSection + i)->Size; j++){
      printf("%c", (dataSection + i)->Data[j]);
    }
    printf("\n\n");
  }

  // free
  for(i = 0; i < runtimeResourceHeader.NumberOfResources; i++){
    free((nameSection + i)->Name);
    free((dataSection + i)->Data);
  }
  free(nameSection);
  free(dataSection);
}

void getMetadataheader(FILE *fp){
  fread(&metadataHeader, sizeof(unsigned char), 30, fp);
}

int main(int argc, char *argv[]){
  FILE *fp;
  long file_size;
  struct stat st;

  if(argc < 2){
    printf("Usage: %s filename\n", argv[0]);
    exit(1);
  }

  fp = fopen(argv[1], "rb");

  if(fp == NULL){
    fprintf(stderr, "Can not open the %s\n", argv[1]);
    exit(1);
  }

  if(stat(argv[1], &st) != 0){
    fprintf(stderr, "Can not open the %s\n", argv[1]);
    exit(1);
  }

  file_size = st.st_size;

  printf("File size : %ld\n", file_size);

  getDosheader(fp);
  getNtHeader(fp);
  getFileHeader(fp);
  getOptionalHeader(fp);
  getSectionHeader(fp);
  getClrHeader(fp);
  getResourceManagerHeader(fp);
  getRuntimeResourceHeader(fp);
  getRuntimeResourceNameAndDataSection(fp);

  fclose(fp);

  return 0;
}
