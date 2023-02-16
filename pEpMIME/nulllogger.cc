// This file is under GNU General Public License 3.0
// see LICENSE.txt

#include "nulllogger.hh"

class NullBuffer : public std::streambuf
{
public:
	virtual int sync() { return 0; }
};

NullBuffer nullbuffer;

std::ostream nulllogger(&nullbuffer);
