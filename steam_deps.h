#pragma once

namespace s_deps {
	typedef long SteamAPICall_t;
	const SteamAPICall_t k_uAPICallInvalid = 0x0;

	class CCallbackBase {
	public:
		CCallbackBase() { m_iCallback = 0; }
		virtual void Run(void* pvParam) = 0;
		int m_iCallback;
	};

	template< /*class T, */ class P >
	class CCallResult : private CCallbackBase {
	public:
		typedef void (/*T::*/*func_t)(P*, bool);
		SteamAPICall_t m_hAPICall;
		//T* m_pObj;
		func_t m_Func;

		CCallResult(){
			//m_hAPICall = k_uAPICallInvalid;
			//m_pObj = nullptr;
			m_Func = nullptr;
			m_iCallback = P::k_iCallback;
		}
		void Set(/*SteamAPICall_t hAPICall,*/ /*T* p,*/ func_t func) {
			//if (m_hAPICall) SteamAPI_UnregisterCallResult(this, m_hAPICall);

			//m_hAPICall = hAPICall;
			//m_pObj = p;
			m_Func = func;

			//if (hAPICall) SteamAPI_RegisterCallResult(this, hAPICall);
		}
		virtual void Run(void* pvParam) override{
			//m_hAPICall = k_uAPICallInvalid;
			(/*m_pObj->*/*m_Func)((P*)pvParam, false);
		}
	};
}