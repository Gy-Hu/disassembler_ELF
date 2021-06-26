#include "../include/baseblock.h"
#include "../include/utility.h"





bool BaseBlock::checkNeedRelo()
{
	int i = insn.size() - 1;
	if ((string(insn[i].mnemonic) == "jmp" || string(insn[i].mnemonic) == "call") && insn[i].size == 5)
	{
		return true;
	}
	else if (insn[i].mnemonic[0] == 'j' && insn[i].size == 6)
	{
		return true;
	}
	return false;
}


bool BaseBlock::checkCallTrueFunction(map<uint64_t, shared_ptr<BaseBlock>> &mbs)
{
	if (string(insn[insn.size() - 1].mnemonic) == "call" )
	{
		auto it = mbs.find(getJmpAddr());
		if (it!=mbs.end())
		{
			if (string(it->second->getFirst().mnemonic) == "push" && string(it->second->getFirst().op_str) == "ebp")
			{
				return true;
			}
		}
	}
	return false;
}

bool BaseBlock::checkIsDirectCallFunction()
{
	if (string(insn[insn.size() - 1].mnemonic) == "call" && string(this->getLast().op_str).substr(0, 2) == "0x")
	{
		return true;
	}
	return false;
}


uint64_t BaseBlock::getJmpAddr()
{
	int ret = 0;
	if (string(this->getLast().mnemonic, 4) == "call" && string(this->getLast().op_str).substr(0,2) == "0x")
	{
		string numStr = string(this->getLast().op_str).substr(2);
		ret = hs2i(numStr);
	}
	return ret;
}

vector<shared_ptr<BaseBlock>> BaseBlock::getInnerNext(map<uint64_t, shared_ptr<BaseBlock>> &mbs, int &info)
{
	info = 0;
	vector<shared_ptr<BaseBlock>> vec;
	auto last = this->getLast();
	string op = string(last.mnemonic);
	string op_str = string(last.op_str);
	if (this->getType() == ord) // �����type=1 Ҳ����˳��ִ�еģ���ȡ���һ��ָ�����һ��
	{
		auto it = mbs.find(last.address + last.size);
		if (it != mbs.end())
		{
			vec.push_back(it->second);
		}
	}
	else if (this->getType() == cal || this->getType() == wcl) //�����ǿ����ת��jmp call ret ��ȡ��ת��
	{
		auto it = mbs.find(last.address + last.size);
		if (it != mbs.end())
		{
			vec.push_back(it->second);
		}
	}
	else if (this->getType() == jp)  //������ת
	{
		if (op_str.substr(0, 2) == "0x")
		{
			int addr = hs2i(op_str.substr(2));
			auto it = mbs.find(addr);
			if (it != mbs.end())
			{
				vec.push_back(it->second);
			}
		}
		else
		{
			info = 1;
		}
	}
	else if (this->getType() == ret)  //������ת
	{
		info = 2;
	}
	else if (this->getType() == cjp)  //������ת
	{
		auto it = mbs.find(last.address + last.size);
		if (it != mbs.end())
		{
			vec.push_back(it->second);
		}

		if (op_str.substr(0, 2) == "0x")
		{
			int addr = hs2i(op_str.substr(2));
			auto it = mbs.find(addr);
			if (it != mbs.end())
			{
				vec.push_back(it->second);
			}
		}
		else
		{
			info = 1;
		}
	}
	else
	{
		info = 3;
	}
	return vec;
}

bool BaseBlock::checkIsDirectJmp()
{
	if (string(insn[insn.size() - 1].mnemonic).substr(0,1) == "j" && string(this->getLast().op_str).substr(0, 2) == "0x")
	{
		return true;
	}
	return false;
}





	





