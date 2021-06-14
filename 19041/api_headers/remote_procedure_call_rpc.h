/*
API: Remote Procedure Call (RPC)
API URL: https://docs.microsoft.com/en-us/windows/win32/api/_rpc/
File Creation Time: 2021-06-07

This file was originally generated by winapi_scraper. 
There is no guarantee that this will compile. Some re-ordering may be necessary.
*/

// Default Header
#include <windows.h>

#ifdef __cplusplus
typedef struct IRpcStubBufferVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IRpcStubBuffer * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IRpcStubBuffer * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IRpcStubBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *Connect )( 
            IRpcStubBuffer * This,
            /* [annotation][in] */ 
            _In_  IUnknown *pUnkServer);
        
        void ( STDMETHODCALLTYPE *Disconnect )( 
            IRpcStubBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *Invoke )( 
            IRpcStubBuffer * This,
            /* [annotation][out][in] */ 
            _Inout_  RPCOLEMESSAGE *_prpcmsg,
            /* [annotation][in] */ 
            _In_  IRpcChannelBuffer *_pRpcChannelBuffer);
        
        IRpcStubBuffer *( STDMETHODCALLTYPE *IsIIDSupported )( 
            IRpcStubBuffer * This,
            /* [annotation][in] */ 
            _In_  REFIID riid);
        
        ULONG ( STDMETHODCALLTYPE *CountRefs )( 
            IRpcStubBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *DebugServerQueryInterface )( 
            IRpcStubBuffer * This,
            /* [annotation][out] */ 
            _Outptr_  void **ppv);
        
        void ( STDMETHODCALLTYPE *DebugServerRelease )( 
            IRpcStubBuffer * This,
            /* [annotation][in] */ 
            _In_  void *pv);
        
        END_INTERFACE
    } IRpcStubBufferVtbl;

    typedef struct IPSFactoryBufferVtbl
    {
        BEGIN_INTERFACE
        
        HRESULT ( STDMETHODCALLTYPE *QueryInterface )( 
            IPSFactoryBuffer * This,
            /* [in] */ REFIID riid,
            /* [annotation][iid_is][out] */ 
            _COM_Outptr_  void **ppvObject);
        
        ULONG ( STDMETHODCALLTYPE *AddRef )( 
            IPSFactoryBuffer * This);
        
        ULONG ( STDMETHODCALLTYPE *Release )( 
            IPSFactoryBuffer * This);
        
        HRESULT ( STDMETHODCALLTYPE *CreateProxy )( 
            IPSFactoryBuffer * This,
            /* [annotation][in] */ 
            _In_  IUnknown *pUnkOuter,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][out] */ 
            _Outptr_  IRpcProxyBuffer **ppProxy,
            /* [annotation][out] */ 
            _Outptr_  void **ppv);
        
        HRESULT ( STDMETHODCALLTYPE *CreateStub )( 
            IPSFactoryBuffer * This,
            /* [annotation][in] */ 
            _In_  REFIID riid,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pUnkServer,
            /* [annotation][out] */ 
            _Outptr_  IRpcStubBuffer **ppStub);
        
        END_INTERFACE
    } IPSFactoryBufferVtbl;
#endif

// API Headers
#include <midles.h>
#include <rpc.h>
#include <rpcasync.h>
#include <rpcdcep.h>
#include <rpcnsi.h>
#include <rpcproxy.h>
#include <rpcssl.h>