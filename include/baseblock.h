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
	vector<shared_ptr<BaseBlock>> getInnerNext(map<uint64_t, shared_ptr<BaseBlock>> &mbs, int &info); //���next��ȷ��info=0������Ϊ����0������0ʱĬ��Ϊ1 ��ʾ��ת��ȷ����ret=>2  ;blockType=-1 => 3
	uint64_t getJmpAddr();


	bool     checkNeedRelo();                 //�Ƿ����һ��ָ������Գ���ת ����������Ҫô��jmp��ָ�Ҫô��call����ָ���Ϊ5��
	bool     checkIsDirectCallFunction();
	bool     checkIsDirectJmp();
	bool     checkCallTrueFunction(map<uint64_t, shared_ptr<BaseBlock>> &bbs);

public:
	vector<cs_insn> insn;
	uint64_t        next[2];

	uint8_t         codeRegionIndex_ = 0;        //�ڵڼ��������
	uint32_t        codeOffset_ = 0;             //�ڵڴ���ε�offset
	bool            hasPreBlock_ = false;        //���������Ƿ�Ϊһ�����Ŀ�ʼ�����Ƿ�ȷ���л����� ������ ��������
private:
	int blockType_ = 0; //�ο� enum bbType  //call =>3, ret=>4 ,jmp =>2 && jg jne ... => 1 &&��others=> 0 && ���call��һ������ĵ�ַҲ����checkCallTrueFunction �� checkIsDirectCallIsFunction��һ�£���-1
	uint32_t remoteHandle_ = -1;

};

#endif