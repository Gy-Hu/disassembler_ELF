#include <stdio.h>
#include <sstream>
#include <fstream>
#include "./include/redasm.h"

using namespace std;

void test(const char *filename)
{
	Redasm *redasm = new Redasm();
	map<uint64_t, cs_insn> *mapCodes = new map<uint64_t, cs_insn>();
	map<uint64_t, shared_ptr<BaseBlock>> *pMapBlocks = new map<uint64_t, shared_ptr<BaseBlock>>();


	redasm->disasmPeFile(*mapCodes, *pMapBlocks, filename);

	ofstream fout;
	fout.open("disasm_code_and_blocks.txt");
	for (auto it = pMapBlocks->begin(); it != pMapBlocks->end(); ++it)
	{
		for (int i = 0; i < it->second->getSize(); ++i)
		{
			fout << hex << it->second->insn[i].address << " : " << it->second->insn[i].mnemonic << " " << it->second->insn[i].op_str << endl;
		}
		fout << "-------------------------------------" << endl;
	}

	delete(mapCodes);
	delete(pMapBlocks);
	delete(redasm);
	redasm = NULL;
	fout.close();
}

int main(int argc, char* argv[])
{
	if (argc != 2)
		return 0;
	test(argv[1]);
}