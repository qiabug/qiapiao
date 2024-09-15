#pragma once

namespace crypt {
	template <unsigned size>
	class Xor_string {
	public:
		wchar_t _string[size];

		//加密
		inline constexpr Xor_string(const wchar_t* string) : _string{}
		{
			wchar_t _key = (wchar_t)size;
			for (unsigned i = 0u; i < size; i++)
			{
				_key += (_string[i] = (string[i] ^ _key));
			}
		}

		//解密
		const wchar_t* decrypt() const
		{
			wchar_t _key = (wchar_t)size;
			wchar_t tmp;
			wchar_t* ret_string = const_cast<wchar_t*>(_string);
			for (unsigned i = 0; i < size; i++)
			{
				tmp = _string[i];
				ret_string[i] = tmp ^ _key;
				_key += tmp;
			}
			return ret_string;
		}

	};
}

#define XorS(name, my_string)    constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(wchar_t))> name(my_string)
#define XorString(my_string) []{ constexpr crypt::Xor_string<(sizeof(my_string)/sizeof(wchar_t))> expr(my_string); return expr; }().decrypt()

