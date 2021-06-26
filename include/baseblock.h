#ifndef __BASE_BLOCK_H__
#define __BASE_BLOCK_H__

#include <capstone.h>
#include <stdint.h>
#include <vector>
#include <map>
#include <string>
#include <memory>

enum bbType
{
	wcl = -1,   //wrong call
	ord = 0,
	cjp = 1,
	jp = 2,
	cal = 3,
	ret = 4
};

using namespace std;

struct BaseBlock
{
public:
	BaseBlock(uint8_t codeRegionIndex, uint32_t codeOffset, bool hasPreBlock)
	{
		codeRegionIndex_ = codeRegionIndex;
		codeOffset_ = codeOffset;
		hasPreBlock = hasPreBlock;

		next[0] = 0;
		next[1] = 0;
	}


	uint8_t  getSize()             {return insn.size();};
	int      getType()             { return blockType_; }
	void     setType(int t)        { blockType_ = t; }
	cs_insn  getFirst()            { return insn[0]; };

	uint32_t getAllLenOfBytes()
	{
		uint32_t ret = 0;
		int count = insn.size();
		for (int i = 0; i < count; ++i)
		{
			ret += insn[i].size;
		}
		return ret;
	};
	cs_insn  getByIndex(int index){
		if (index < (insn.size() - 1) && index >= 0)
			return insn[index];
		else
			return insn[insn.size() - 1];
	};
	cs_insn  getLast(){
		int index = insn.size();
		return insn[index - 1];
	};
	vector<shared_ptr<BaseBlock>> getInnerNext(map<uint64_t, shared_ptr<BaseBlock>> &mbs, int &info); //如果next明确则info=0，否则为大于0，大于0时默认为1 表示跳转不确定，ret=>2  ;blockType=-1 => 3
	uint64_t getJmpAddr();


	bool     checkNeedRelo();                 //是否最后一个指令是相对长跳转 两个条件（要么是jmp类指令，要么是call而且指令长度为5）
	bool     checkIsDirectCallFunction();
	bool     checkIsDirectJmp();
	bool     checkCallTrueFunction(map<uint64_t, shared_ptr<BaseBlock>> &bbs);

public:
	vector<cs_insn> insn;
	uint64_t        next[2];

	uint8_t         codeRegionIndex_ = 0;        //在第几个代码段
	uint32_t        codeOffset_ = 0;             //在第代码段的offset
	bool            hasPreBlock_ = false;        //本基本块是否为一个树的开始，即是否确定有基本块 连接着 本基本块
private:
	int blockType_ = 0; //参考 enum bbType  //call =>3, ret=>4 ,jmp =>2 && jg jne ... => 1 &&　others=> 0 && 如果call了一个错误的地址也就是checkCallTrueFunction 与 checkIsDirectCallIsFunction不一致，则-1
	uint32_t remoteHandle_ = -1;

};

#endif