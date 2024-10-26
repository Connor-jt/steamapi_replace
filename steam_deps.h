#pragma once

namespace s_deps {

	typedef int HSteamPipe;
	typedef int HSteamUser;

	typedef long SteamAPICall_t;
	//const SteamAPICall_t k_uAPICallInvalid = 0x0;

	#pragma pack( push, 8 )
	/// Internal structure used in manual callback dispatch
	struct CallbackMsg_t
	{
		HSteamUser m_hSteamUser; // Specific user to whom this callback applies.
		int m_iCallback; // Callback identifier.  (Corresponds to the k_iCallback enum in the callback structure.)
		unsigned char* m_pubParam; // Points to the callback structure
		int m_cubParam; // Size of the data pointed to by m_pubParam
	};
	#pragma pack( pop )


	class CCallbackBase
	{
	public:
		CCallbackBase() { m_nCallbackFlags = 0; m_iCallback = 0; }
		// don't add a virtual destructor because we export this binary interface across dll's
		virtual void Run(void* pvParam) = 0;
		virtual void Run(void* pvParam, bool bIOFailure, SteamAPICall_t hSteamAPICall) = 0;
		int GetICallback() { return m_iCallback; }
		virtual int GetCallbackSizeBytes() = 0;

		//protected:
		enum { k_ECallbackFlagsRegistered = 0x01, k_ECallbackFlagsGameServer = 0x02 };
		unsigned char m_nCallbackFlags;
		int m_iCallback;
		friend class CCallbackMgr;

	private:
		CCallbackBase(const CCallbackBase&);
		CCallbackBase& operator=(const CCallbackBase&);
	};

	template< class T, class P >
	class CCallResult : private CCallbackBase
	{
	public:
		typedef void (T::* func_t)(P*, bool);

		CCallResult();
		~CCallResult();

		void Set(SteamAPICall_t hAPICall, T* p, func_t func);
		bool IsActive() const;
		void Cancel();

		void SetGameserverFlag() { m_nCallbackFlags |= k_ECallbackFlagsGameServer; }
	private:
		virtual void Run(void* pvParam) S_OVERRIDE;
		virtual void Run(void* pvParam, bool bIOFailure, SteamAPICall_t hSteamAPICall) S_OVERRIDE;
		virtual int GetCallbackSizeBytes() S_OVERRIDE { return sizeof(P); }

		SteamAPICall_t m_hAPICall;
		T* m_pObj;
		func_t m_Func;
	};
}