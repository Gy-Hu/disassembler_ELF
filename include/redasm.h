#ifndef __REDASM_H__
#define __REDASM_H__

#include "BaseBlock.h"
#include <memory>
#include <stdio.h>


#define BLOCK_MAX_SIZE 25    //for once we disasm a set of code by byte, 25 will be in best performance , change it will not effect the results
#define FIXED_SIZE -1
#pragma comment(lib, "capstone.lib")

using namespace std;

typedef struct _CodeRegion
{
	const uint8_t *code;
	size_t        code_size;        
	uint64_t      address;     //startAddr
}CodeRegion,*PCodeRegion;


class Redasm
{
public:


	bool disasmPeFile(
		map<uint64_t, cs_insn> &mapCodes,
		map<uint64_t, shared_ptr<BaseBlock>> &mapBlocks,
		const char* fileName,
		const size_t count = BLOCK_MAX_SIZE,
		const cs_mode mode = CS_MODE_32
		);


private:
	void disasm(map<uint64_t, cs_insn> &codes,
		map<uint64_t, shared_ptr<BaseBlock>> &blocks,
		const uint64_t startAddr,
		const CodeRegion *regions,
		const uint8_t regionCount,
		const size_t count,
		const csh &handle,
		const cs_mode mode);

	/*
	Recursively disassemble binary code and store in the baseblock list
	regions[0] must contain the entry point of the program
	  @insn: array of instructions filled in by this API.
	  @pBaseBlock, receive the baseblocks
	  @code: buffer containing raw binary code to be disassembled.
	  @code_size: size of the above code buffer.
	  @address: address of the first instruction in given raw code buffer.
	  @cs_mode: disasm by 16\32\64 bit
	  @return count of BaseBlock
	*/
	void disasmFunction(map<uint64_t, cs_insn> &codes,
		map<uint64_t, shared_ptr<BaseBlock>> &blocks,
		const uint64_t startAddr,
		const CodeRegion *regions,
		const uint8_t regionCount,
		const size_t count,
		const csh &handle,
		const cs_mode mode);


	map<uint64_t,shared_ptr<BaseBlock>> getMapBlocks()
	{
		return mapBlocks_;	
	}

	map<uint64_t, shared_ptr<BaseBlock>> getMapCallBlocks()
	{
		map<uint64_t, shared_ptr<BaseBlock>> mapCallBlocks;
		
		for (auto it = mapBlocks_.begin(); it != mapBlocks_.end(); ++it)
		{
			if (string(it->second->getLast().mnemonic) == "call")
				mapCallBlocks[it->second->getLast().address] = it->second;
		}
		
		return mapCallBlocks;
	}

	/*
	return the filtered blocks
	@filter is the name of the ASMCode,such as 'call' 
	@codeLen is the length of the ASMCode
	*/
	map<uint64_t,shared_ptr<BaseBlock>> getMapBlocks(string filter,int codeLen=0)
	{
		if(filter=="")
			return mapBlocks_;
		else
		{
			map<uint64_t,shared_ptr<BaseBlock>> tmpBlocks;

			for(auto it=mapBlocks_.begin();it!=mapBlocks_.end();++it)
			{
				if((it->second->getLast().mnemonic == filter) && (codeLen>0?it->second->getLast().size == codeLen :true) )
				{
					tmpBlocks.insert(map<uint64_t,shared_ptr<BaseBlock>>::value_type(it->first,it->second));
				}
			}
			return tmpBlocks;
		}
	}


private:
	struct Shared
	{
		map<uint64_t,shared_ptr<BaseBlock>> &mapBlock;
		const csh &handle;
		const CodeRegion *codeRegion;
		const uint8_t regionCount;
	};


private:
	uint64_t entryAddr_ = 0;
	map<uint64_t,shared_ptr<BaseBlock>> mapBlocks_;
	map<uint64_t, shared_ptr<BaseBlock>> tmpMapBlock_;  //used by disasm function,save tmpBlocks

private:
	inline int cxtoi(const char* p)
	{
		int nValue = 0;          
		sscanf(p, "%x", &nValue);
		return nValue;
	}

	int addrOfRegion(const CodeRegion *regions,uint64_t address,int regCount)
	{
		for(int i=0;i<regCount;++i)
		{
			if(regions[i].address <= address && (regions[i].address + regions[i].code_size)>=address)
				return i;
		}
		return -1;
	}

	shared_ptr<BaseBlock> disasm_base_block(uint64_t &nextOffsetOne, int8_t &nextIndexOne, uint64_t &nextOffsetTwo, int8_t &nextIndexTwo, Shared &sh, const size_t count, uint64_t offset, uint8_t indexOfRegion);

	void tile_and_split(map<uint64_t,shared_ptr<BaseBlock>> &mapBlocksOut,map<uint64_t,shared_ptr<BaseBlock>> &mapBlocksIn,map<uint64_t,cs_insn> &codes);
	
	uint32_t getNextStartAddrInRegions(const map<uint64_t, shared_ptr<BaseBlock>> &blocks, const CodeRegion *regions,
		const uint8_t regionCount, uint32_t nowAddr);
};
#endif
