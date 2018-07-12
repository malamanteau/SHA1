#define NOMINMAX

#include <iostream>
#include <string>
#include "../../Handy.hpp"
#include "../../HandyExtended.hpp"

int main()
{
	std::unordered_set<std::string> coll;

	while (true)
	{
		SHA1 sha = Handy::SHA1::NewUUID();

		std::string str = sha.String128Hyphenated();

		if (Handy::Contains(coll, str))
			std::cerr << "Duplicate FOUND! " << str << std::endl;

		coll.insert(str);
	}

	return 0;
}