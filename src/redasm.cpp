#include "../include/utility.h"
#include "../include/redasm.h"
#include "../include/pe.h"
#include <tchar.h>
#include <shlwapi.h>
#include <utility>
#include <list>

using namespace std;


bool Redasm::disasmPeFile(map<uint64_t, cs_insn> &mapCodes, map<uint64_t, shared_ptr<BaseBlock>> &mapBlocks, const char* fileName, const size_t count /*= BLOCK_MAX_SIZE*/, const cs_mode mode /*= CS_MODE_32 */)
{
	//step one read PeInfo in memory And prepare the data used by Disasm
	PeInfo peInfo;
	parseError error;

	if (!PE::Parser(fileName, peInfo, error))
	{
		return false;
	}

	int index = 0; //#*# only choose the first code segment by default
	uint64_t addr = peInfo.vSectionHeaders[index].VirtualAddress + peInfo.ntHeader.OptionalHeader.ImageBase;

	int len = peInfo.vSectionHeaders[index].Misc.VirtualSize;  //length of this segment's code 
	unsigned char* buf = new unsigned char[len];


	uint64_t entryAddr = peInfo.ntHeader.OptionalHeader.AddressOfEntryPoint + peInfo.ntHeader.OptionalHeader.ImageBase;

	const int regionCount = 1;

	ifstream fin;
	fin.open(fileName, ios::binary);

	fin.seekg(peInfo.vSectionHeaders[index].PointerToRawData, ios::beg);
	fin.read((char*)buf, len);

	fin.close();


	CodeRegion region =
	{
		buf,
		len, //#*#
		addr
	};


	csh handle;
	if (cs_open(CS_ARCH_X86, mode, &handle))
	{
		printf("ERROR: Failed to initialize engine!\n");
		return false;
	}


	this->disasm(mapCodes, mapBlocks, entryAddr, &region, regionCount, count, handle, mode);

	cs_close(&handle);

	if (this->getMapBlocks().size() > 0)
	{
		mapBlocks = mapBlocks_;
		delete(buf);
		return true;
	}
	else
	{
		delete(buf);
		return false;
	}
}



void Redasm::disasmFunction(map<uint64_t, cs_insn> &codes,
	map<uint64_t, shared_ptr<BaseBlock>> &blocks,
	const uint64_t startAddr,
	const CodeRegion *regions,
	const uint8_t regionCount,
	const size_t count,
	const csh &handle,
	const cs_mode mode){

	

	//regionCount must be greater than one
	if(regionCount < 1)
		return;
	
	if (entryAddr_ == 0)
		entryAddr_ = startAddr;
	

	
	struct Shared sh = 
	{
		tmpMapBlock_,
		handle,
		regions,
		regionCount
	};


	uint64_t offsetOne = 0;
	uint64_t offsetTwo = 0;
	int8_t   indexOne = -1;
	int8_t   indexTwo = -1;

	

	
	list<pair<uint64_t, uint8_t>> addrList;
	//first call disasm_base_block and fill the addrList
	
	if (startAddr==0)
		disasm_base_block(offsetOne, indexOne, offsetTwo, indexTwo, sh, count, 0, 0);
	else
	{
		bool inRegions = false;
		//find the regionIndex,and the offset , that is ,fill the last two paras of the 'disasm_base_block' func
		for (int i = 0; i < regionCount; ++i)
		{
			if (regions[i].address <= startAddr && (regions[i].code_size + regions[i].address) >startAddr)
			{
				int newIndex = i;
				uint64_t newOffset = startAddr - regions[i].address;
				disasm_base_block(offsetOne, indexOne, offsetTwo, indexTwo, sh, count, newOffset, newIndex);
				inRegions = true;
				break;
			}
		}
		if (!inRegions)
			disasm_base_block(offsetOne, indexOne, offsetTwo, indexTwo, sh, count, 0, 0);
	}

	if (indexOne >= 0)
		addrList.push_back(pair<uint64_t, uint8_t>(offsetOne,indexOne));
	if (indexTwo >=0)
		addrList.push_back(pair<uint64_t, uint8_t>(offsetTwo, indexTwo));

	for (auto it = addrList.begin(); it != addrList.end(); ++it)
	{
		disasm_base_block(offsetOne, indexOne, offsetTwo, indexTwo, sh, count, it->first, it->second);
		if (indexOne >= 0)
			addrList.push_back(pair<uint64_t, uint8_t>(offsetOne, indexOne));
		if (indexTwo >= 0)
			addrList.push_back(pair<uint64_t, uint8_t>(offsetTwo, indexTwo));
	}

}

//**********************************************************************************
//���ߣ�lonely.wm
//������������������
//���ã�����capstone���������һ�λ�����
//����1,2,3,4�� ����������������������������ģ�һ����ֱ�������ģ�һ������ת�ģ���Ϣ
//����sh��Ϊ�˼��ٴ���������һЩ������Ϣͳһ����sh�У����Բο�sh�ṹ��
//����count��ÿ�η��������ָ������Ĭ��Ϊ25����һЩ��������£���Ҫ�ݹ���ã�count�����������������
//����offset������࿪ʼ��offset
//����index������࿪ʼ�Ĵ���ε�index
//**********************************************************************************
shared_ptr<BaseBlock> Redasm::disasm_base_block(uint64_t &nextOffsetOne, int8_t &nextIndexOne, uint64_t &nextOffsetTwo, int8_t &nextIndexTwo, Shared &sh, const size_t count, uint64_t offset, uint8_t index)
{

	nextOffsetOne = 0;
	nextOffsetTwo = 0;
	nextIndexOne = -1;
	nextIndexTwo = -1;

	cs_insn *insn;
	uint64_t startAddr = sh.codeRegion[index].address + offset;
	if (startAddr >= sh.codeRegion[sh.regionCount - 1].address + sh.codeRegion[sh.regionCount - 1].code_size)
		return nullptr;

	if (sh.mapBlock.find(startAddr) != sh.mapBlock.end())    //if the mapBlock contains the startAddr, we just return ,avoid repeat
	{
		return nullptr;
	}

	size_t rcount = cs_disasm(sh.handle,sh.codeRegion[index].code+offset, sh.codeRegion[index].code_size,sh.codeRegion[index].address+offset, count, &insn);  //just plus offset
	

	//if the code can't be disasm
	if(rcount<=0)
	{
		return nullptr;
	}
	//if the offset > codesize we don't neend to disasm it
	if(offset > sh.codeRegion[index].code_size)
	{
		return nullptr;
	}
	//if mapBlock contains this block,then we don't neet to analysis it
	if(sh.mapBlock.find(insn[0].address) != sh.mapBlock.end())
	{
		return nullptr;
	}

	
	for(int i=0;i<rcount;i++)
	{
			
				
		//if there is a shift instruction , we will split insn to baseblocks
		//we compare twice, because this methon will more efficient
		if(insn[i].mnemonic[0] == 'j' || insn[i].mnemonic[0] == 'c' || insn[i].mnemonic[0] == 'r')
		{
			string mneonic(insn[i].mnemonic);
			if(insn[i].mnemonic[0] == 'j' || mneonic == "call" || mneonic == "ret" || mneonic == "retn")
			{
				//there we get three baseblocks, father on and it's two children
				shared_ptr<BaseBlock> pbb = shared_ptr<BaseBlock>(new BaseBlock(index, offset, false));

				for(int j=0;j<=i;j++)
				{
					pbb->insn.push_back(insn[j]);
				}

				//get next[0] and it's index: newIndex1 , if index<0 we don't deel with it

				int newIndex1 = 0;
				pbb->next[0] = insn[i].address + insn[i].size;
				if (mneonic == "ret" || mneonic == "retn")
					newIndex1 = -1;
				else
					newIndex1 = addrOfRegion(sh.codeRegion, pbb->next[0], sh.regionCount);
					

				//get next[1] and it's index: newIndex2 , if index<0 we don't deel with it
				int newIndex2 = -1 ;
				uint64_t newAddr;
				if (insn[i].mnemonic[0] == 'j' || mneonic == "call")
				{
					newAddr = cxtoi(insn[i].op_str);
					newIndex2 = addrOfRegion(sh.codeRegion, newAddr, sh.regionCount);
				}

				if (newIndex2 >= 0)
				{
					pbb->next[1] = newAddr;
				}
						
				sh.mapBlock.insert(map<uint64_t,shared_ptr<BaseBlock>>::value_type(pbb->insn[0].address,pbb));
				cs_free(insn, rcount);

				if(newIndex1>=0)
				{
					nextOffsetOne = pbb->next[0] - sh.codeRegion[newIndex1].address;
					nextIndexOne = newIndex1;
					//disasm_base_block(sh,count,pbb->next[0]-sh.codeRegion[newIndex1].address,newIndex1);
				}

				if(newIndex2>=0)
				{
					nextOffsetTwo = pbb->next[1] - sh.codeRegion[newIndex2].address;
					nextIndexTwo = newIndex2;
					//disasm_base_block(sh,count,pbb->next[1]-sh.codeRegion[newIndex2].address,newIndex2);
				}

				//we get the baseblocks so the loop useless
				return pbb;
			}

		}
		else if(i==rcount -1 && count < 800)  //������800������ ���պ�25��ָ������һ������ת����ʱ�޷�֪��ֱ����������һ��ָ�������Ҫ�ݹ�
		{
			//if the all instructions have on shift ins , we will store them to on base blocks but it has only one child
			disasm_base_block(nextOffsetOne,nextIndexOne,nextOffsetTwo,nextIndexTwo,sh,2*count,offset,index);
		}
		
	}

	return nullptr;
}

//**********************************************************************************
//���ߣ�lonely.wm
//��������չƽ���ָ������
//���ã���ԭʼ�������mapչƽ���ص����ֽ��кϲ��������ص������飬ͬʱ��hasPreBlock��ֵ
//����mapBlocksOut�� ���map
//����mapBlocksIn�� ����map
//����codes�����������code
//**********************************************************************************
void Redasm::tile_and_split(map<uint64_t,shared_ptr<BaseBlock>> &mapBlocksOut,map<uint64_t,shared_ptr<BaseBlock>> &mapBlocksIn,map<uint64_t,cs_insn> &codes)
{
	mapBlocksOut.clear(); 
	entryAddr_ = 0;

	//tile
	map<uint64_t,bool> splitSign;
	for(auto it=mapBlocksIn.begin();it!=mapBlocksIn.end();++it)
	{
		for(int j=0;j<it->second->getSize();++j)
		{
			codes[it->second->insn[j].address]=it->second->insn[j];
			splitSign[it->second->insn[j].address]+=0;
			if(j==0)
			{
				//first one
				splitSign[it->second->insn[j].address] = true;
			}
		}
	}

	//split
	splitSign.begin()->second=true;  // the first code

	auto it1=codes.begin();
	auto it2=splitSign.begin();
	shared_ptr<BaseBlock> pbb = nullptr;
	for(;it1!=codes.end();++it1,++it2)
	{
		if(it2->second)
		{

			bool hasPreBlock = false;
			if (!(mapBlocksIn[it1->first]->next[0] == 0 && mapBlocksIn[it1->first]->next[1] == 0))
				hasPreBlock = true;

			pbb = shared_ptr<BaseBlock>(new BaseBlock(mapBlocksIn[it1->first]->codeRegionIndex_,
								mapBlocksIn[it1->first]->codeOffset_,
								hasPreBlock));
			pbb->next[0] = mapBlocksIn[it1->first]->next[0];
			pbb->next[1] = mapBlocksIn[it1->first]->next[1];

			pbb->insn.push_back(it1->second);
			mapBlocksOut[it2->first] = pbb;
		}
		else
		{
			pbb->insn.push_back(it1->second);
		}
	}

}

//**********************************************************************************
//���ߣ�lonely.wm
//����������ȡĳ��������п�ʼ�����ĵ�ַ
//���ã��ڷ��������е��ã���ȡ��һ����ʼ�����ĵ�ַ
//����blocks�� ���еĿ�
//����regions�� ����region�����ַ
//����regionCount��region����
//����nowAddr����ǰ����ൽ�ĵ�ַ
//**********************************************************************************
uint32_t Redasm::getNextStartAddrInRegions(const map<uint64_t, shared_ptr<BaseBlock>> &blocks, const CodeRegion *regions,const uint8_t regionCount, uint32_t nowAddr)
{
	#define CALL_START "\x55\x8B\xEC"
	unsigned char call_start[3];
	call_start[0] = 0x55;
	call_start[1] = 0x8B;
	call_start[2] = 0xEC;


	if (nowAddr == 0)
		nowAddr == blocks.begin()->first;

	auto it = blocks.begin();
	for (; it != blocks.end(); ++it)
	{
		if (it->first >= nowAddr)
		{
			auto nextIt = it;
			nextIt++;
			if (nextIt != blocks.end())
			{
				//if there is a large empty area in the mid of the two blocks,we should start from there and disasm 
				uint32_t preAddr = it->second->getLast().address + it->second->getLast().size;
				
				//�����������������ļ������32������Ҫ������������ɨ�裬�ҵ�push ebp ��mov ebp,esp����ͷ�ģ�Ҳ���Ǻ�������Ϊ�µĿ�ʼ
				if (preAddr <= (nextIt->second->getFirst().address - 8*4))
				{
					//��ȡ�����С
					uint32_t emptySize = nextIt->second->getFirst().address - preAddr;
					//��ȡ������һ��addr����
					int indexOfRegion = addrOfRegion(regions, preAddr, regionCount);
					if (indexOfRegion != -1)
					{
						//���������ɨ���������
						//��ȡ ��ʼ��Ե�ƫ�ƣ��Ա��ҵ�����
						uint32_t preOffset = preAddr - regions[indexOfRegion].address;

						//loop find the first start of a function 'push ebp ; mov ebp ,esp'
						for (auto i = 0; i < emptySize; i++)
						{
							//���������ƫ�� �����������������Ĵ�С
							if (i + preOffset <= regions[indexOfRegion].code_size)
							{
								//�Ƚ�����ط��Ĵ����ǲ�������Ҫ�� ,����� 
								if (memcmp((void*)&(regions[indexOfRegion].code[preOffset+i]), &call_start[0], 3) == 0)
								{
									return preAddr + i ;
								}
							}
							
						}
						
					}
				}
			}
		}
	}
	//if we can't find it,then return the next addr of the last block ,and if the last block's next addr <= nowAddr ,we return nowAddr +8
	--it;
	auto lastAddr = it->second->getLast().address + it->second->getLast().size;
	if (nowAddr >= lastAddr)
		return nowAddr + 100;
	else
		return lastAddr;
	
}

void Redasm::disasm(map<uint64_t, cs_insn> &codes, map<uint64_t, shared_ptr<BaseBlock>> &blocks, const uint64_t startAddr, const CodeRegion *regions, const uint8_t regionCount, const size_t count, const csh &handle, const cs_mode mode)
{
	disasmFunction(codes, blocks, startAddr, regions, regionCount, count, handle, mode);

	uint64_t nextStartAddr = getNextStartAddrInRegions(tmpMapBlock_, regions, regionCount, 0);
	while (true)
	{
		//nextStartAddr is out of range
		if (nextStartAddr >= regions[regionCount - 1].address + regions[regionCount - 1].code_size)
			break;
		disasmFunction(codes, blocks, nextStartAddr, regions, regionCount, count, handle, mode);
		nextStartAddr = getNextStartAddrInRegions(tmpMapBlock_, regions, regionCount, nextStartAddr);
	}


	tile_and_split(blocks, tmpMapBlock_, codes);

	//for (auto it = tmpMapBlock_.begin(); it != tmpMapBlock_.end(); ++it)
	//{
	//	delete(it->second);
	//}

	mapBlocks_ = blocks;
	tmpMapBlock_.clear();
}


