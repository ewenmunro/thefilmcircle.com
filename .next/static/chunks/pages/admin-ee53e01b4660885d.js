(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[964],{5683:function(e,t,n){var r,u,o=1/0,i=/[^\x00-\x2f\x3a-\x40\x5b-\x60\x7b-\x7f]+/g,s=/[\xc0-\xd6\xd8-\xf6\xf8-\xff\u0100-\u017f]/g,c="\ud800-\udfff",a="\\u2700-\\u27bf",l="a-z\\xdf-\\xf6\\xf8-\\xff",f="A-Z\\xc0-\\xd6\\xd8-\\xde",d="\\xac\\xb1\\xd7\\xf7\\x00-\\x2f\\x3a-\\x40\\x5b-\\x60\\x7b-\\xbf\\u2000-\\u206f \\t\\x0b\\f\\xa0\\ufeff\\n\\r\\u2028\\u2029\\u1680\\u180e\\u2000\\u2001\\u2002\\u2003\\u2004\\u2005\\u2006\\u2007\\u2008\\u2009\\u200a\\u202f\\u205f\\u3000",x="['’]",h="["+d+"]",p="[\\u0300-\\u036f\\ufe20-\\ufe23\\u20d0-\\u20f0]",j="["+l+"]",g="[^"+c+d+"\\d+"+a+l+f+"]",v="(?:\ud83c[\udde6-\uddff]){2}",m="[\ud800-\udbff][\udc00-\udfff]",b="["+f+"]",y="(?:"+j+"|"+g+")",_="(?:"+x+"(?:d|ll|m|re|s|t|ve))?",E="(?:"+x+"(?:D|LL|M|RE|S|T|VE))?",A="(?:"+p+"|\ud83c[\udffb-\udfff])?",O="[\\ufe0e\\ufe0f]?",w="(?:\\u200d(?:"+["[^"+c+"]",v,m].join("|")+")"+O+A+")*",C="(?:"+["["+a+"]",v,m].join("|")+")"+(O+A+w),N=RegExp(x,"g"),Z=RegExp(p,"g"),S=RegExp([b+"?"+j+"+"+_+"(?="+[h,b,"$"].join("|")+")","(?:"+b+"|"+g+")+"+E+"(?="+[h,b+y,"$"].join("|")+")",b+"?"+y+"+"+_,b+"+"+E,"\\d+",C].join("|"),"g"),I=/[a-z][A-Z]|[A-Z]{2,}[a-z]|[0-9][a-zA-Z]|[a-zA-Z][0-9]|[^a-zA-Z0-9 ]/,L="object"==typeof n.g&&n.g&&n.g.Object===Object&&n.g,k="object"==typeof self&&self&&self.Object===Object&&self,R=L||k||Function("return this")(),U=(r={À:"A",Á:"A",Â:"A",Ã:"A",Ä:"A",Å:"A",à:"a",á:"a",â:"a",ã:"a",ä:"a",å:"a",Ç:"C",ç:"c",Ð:"D",ð:"d",È:"E",É:"E",Ê:"E",Ë:"E",è:"e",é:"e",ê:"e",ë:"e",Ì:"I",Í:"I",Î:"I",Ï:"I",ì:"i",í:"i",î:"i",ï:"i",Ñ:"N",ñ:"n",Ò:"O",Ó:"O",Ô:"O",Õ:"O",Ö:"O",Ø:"O",ò:"o",ó:"o",ô:"o",õ:"o",ö:"o",ø:"o",Ù:"U",Ú:"U",Û:"U",Ü:"U",ù:"u",ú:"u",û:"u",ü:"u",Ý:"Y",ý:"y",ÿ:"y",Æ:"Ae",æ:"ae",Þ:"Th",þ:"th",ß:"ss",Ā:"A",Ă:"A",Ą:"A",ā:"a",ă:"a",ą:"a",Ć:"C",Ĉ:"C",Ċ:"C",Č:"C",ć:"c",ĉ:"c",ċ:"c",č:"c",Ď:"D",Đ:"D",ď:"d",đ:"d",Ē:"E",Ĕ:"E",Ė:"E",Ę:"E",Ě:"E",ē:"e",ĕ:"e",ė:"e",ę:"e",ě:"e",Ĝ:"G",Ğ:"G",Ġ:"G",Ģ:"G",ĝ:"g",ğ:"g",ġ:"g",ģ:"g",Ĥ:"H",Ħ:"H",ĥ:"h",ħ:"h",Ĩ:"I",Ī:"I",Ĭ:"I",Į:"I",İ:"I",ĩ:"i",ī:"i",ĭ:"i",į:"i",ı:"i",Ĵ:"J",ĵ:"j",Ķ:"K",ķ:"k",ĸ:"k",Ĺ:"L",Ļ:"L",Ľ:"L",Ŀ:"L",Ł:"L",ĺ:"l",ļ:"l",ľ:"l",ŀ:"l",ł:"l",Ń:"N",Ņ:"N",Ň:"N",Ŋ:"N",ń:"n",ņ:"n",ň:"n",ŋ:"n",Ō:"O",Ŏ:"O",Ő:"O",ō:"o",ŏ:"o",ő:"o",Ŕ:"R",Ŗ:"R",Ř:"R",ŕ:"r",ŗ:"r",ř:"r",Ś:"S",Ŝ:"S",Ş:"S",Š:"S",ś:"s",ŝ:"s",ş:"s",š:"s",Ţ:"T",Ť:"T",Ŧ:"T",ţ:"t",ť:"t",ŧ:"t",Ũ:"U",Ū:"U",Ŭ:"U",Ů:"U",Ű:"U",Ų:"U",ũ:"u",ū:"u",ŭ:"u",ů:"u",ű:"u",ų:"u",Ŵ:"W",ŵ:"w",Ŷ:"Y",ŷ:"y",Ÿ:"Y",Ź:"Z",Ż:"Z",Ž:"Z",ź:"z",ż:"z",ž:"z",Ĳ:"IJ",ĳ:"ij",Œ:"Oe",œ:"oe",ŉ:"'n",ſ:"ss"},function(e){return null==r?void 0:r[e]}),T=Object.prototype.toString,z=R.Symbol,P=z?z.prototype:void 0,D=P?P.toString:void 0;function F(e){return null==e?"":function(e){if("string"==typeof e)return e;if("symbol"==typeof(t=e)||t&&"object"==typeof t&&"[object Symbol]"==T.call(t))return D?D.call(e):"";var t,n=e+"";return"0"==n&&1/e==-o?"-0":n}(e)}var M=(u=function(e,t,n){return e+(n?"-":"")+t.toLowerCase()},function(e){var t;return function(e,t,n,r){for(var u=-1,o=e?e.length:0;++u<o;)n=t(n,e[u],u,e);return n}(function(e,t,n){if(e=F(e),void 0===t){var r;return(r=e,I.test(r))?e.match(S)||[]:e.match(i)||[]}return e.match(t)||[]}(((t=F(t=e))&&t.replace(s,U).replace(Z,"")).replace(N,"")),u,"")});e.exports=M},8195:function(e,t,n){(window.__NEXT_P=window.__NEXT_P||[]).push(["/admin",function(){return n(4866)}])},9724:function(e,t,n){"use strict";n.d(t,{Z:function(){return c}});var r=n(5893),u=n(1664),o=n.n(u),i=n(7294),s=n(2373);function c(e){let{username:t}=(0,i.useContext)(s.S);return t?e.children:e.fallback||(0,r.jsx)(o(),{href:"/enter",children:"You must sign in"})}},5864:function(e,t,n){"use strict";n.d(t,{Z:function(){return i}});var r=n(5893),u=n(9008),o=n.n(u);function i(e){let{title:t="The Film Circle",description:n="Inspire | Create | Share",image:u="https://thefilmcircle.com/public/the_film_circle_logo.png"}=e;return(0,r.jsxs)(o(),{children:[(0,r.jsx)("title",{children:t}),(0,r.jsx)("meta",{name:"twitter:title",content:t}),(0,r.jsx)("meta",{name:"twitter:description",content:n}),(0,r.jsx)("meta",{name:"twitter:image",content:u}),(0,r.jsx)("meta",{property:"og:title",content:t}),(0,r.jsx)("meta",{property:"og:description",content:n}),(0,r.jsx)("meta",{property:"og:image",content:u})]})}},6383:function(e,t,n){"use strict";n.d(t,{Z:function(){return i}});var r=n(5893),u=n(1664),o=n.n(u);function i(e){let{posts:t,admin:n}=e;return t?t.map(e=>(0,r.jsx)(s,{post:e,admin:n},e.slug)):null}function s(e){let{post:t,admin:n=!1}=e,u=null==t?void 0:t.content.trim().split(/\s+/g).length,i=(u/100+1).toFixed(0);return(0,r.jsxs)("div",{className:"card",children:[(0,r.jsx)(o(),{href:"/".concat(t.username),children:(0,r.jsxs)("p",{children:["By @",t.username]})}),(0,r.jsx)(o(),{href:"/".concat(t.username,"/").concat(t.slug),children:(0,r.jsx)("h2",{children:t.title})}),(0,r.jsx)("footer",{children:(0,r.jsxs)("span",{children:[u," words. ",i," min(s) read."]})}),n&&(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)(o(),{href:"/admin/".concat(t.slug),children:(0,r.jsx)("h3",{children:(0,r.jsx)("button",{className:"btn-blue",children:"Edit"})})}),t.published?(0,r.jsx)("p",{className:"text-success",children:"Live!"}):(0,r.jsx)("p",{className:"text-danger",children:"Not Live!"})]})]})}},4866:function(e,t,n){"use strict";n.r(t),n.d(t,{default:function(){return m}});var r=n(5893),u=n(7809),o=n.n(u),i=n(1664),s=n.n(i),c=n(6383),a=n(9724),l=n(5864),f=n(2373),d=n(8233),x=n(1163),h=n(7294),p=n(6552),j=n(5683),g=n.n(j),v=n(6501);function m(e){let{}=e;return(0,r.jsx)("main",{children:(0,r.jsxs)(a.Z,{children:[(0,r.jsx)(l.Z,{title:"My Job Posts",description:"My jobs posted to The Film Circle"}),(0,r.jsx)(y,{}),(0,r.jsx)(b,{})]})})}function b(){let e=d.RZ.collection("users").doc(d.I8.currentUser.uid).collection("posts"),t=e.orderBy("createdAt"),[n]=(0,p.Kx)(t),u=null==n?void 0:n.docs.map(e=>e.data());return(0,r.jsxs)(r.Fragment,{children:[u&&u.length>0?(0,r.jsx)("h1",{children:"My Job Posts"}):null,(0,r.jsx)(c.Z,{posts:u,admin:!0})]})}function y(){let e=(0,x.useRouter)(),{username:t}=(0,h.useContext)(f.S),[n,u]=(0,h.useState)(""),i=encodeURI(g()(n)),c=n.length>3,a=async r=>{r.preventDefault();let u=d.I8.currentUser.uid,o=d.RZ.collection("users").doc(u).collection("posts").doc(i),s={title:n,slug:i,uid:u,username:t,published:!1,content:"Write your job post here",createdAt:(0,d.Bt)(),updatedAt:(0,d.Bt)(),heartCount:0};await o.set(s),v.ZP.success("Job Post Created!"),e.push("/admin/".concat(i))};return(0,r.jsxs)(r.Fragment,{children:[(0,r.jsx)("h1",{children:"Create New Job Post"}),(0,r.jsx)("p",{children:"For consistency and stronger SEO results, write your new job post title in following way:"}),(0,r.jsx)("p",{children:(0,r.jsx)("strong",{children:"DD/MM/YYYY: Location (e.g. Sydney CBD, Australia), state whether 'paid' or 'unpaid', description of what you are looking for (e.g. 1x female actor, 20-27, Caucasian, blonde hair, blue eyes)"})}),(0,r.jsxs)("p",{children:["If unsure, look to the ",(0,r.jsx)(s(),{href:"/",children:"home page"})," for reference."]}),(0,r.jsxs)("form",{onSubmit:a,children:[(0,r.jsx)("input",{value:n,onChange:e=>u(e.target.value),placeholder:"Write new job post title here",className:o().input}),(0,r.jsxs)("p",{children:[(0,r.jsx)("strong",{children:"Slug:"})," ",i]}),(0,r.jsx)("button",{type:"submit",disabled:!c,className:"btn-green",children:"Create New Job Post"})]})]})}},7809:function(e){e.exports={container:"Admin_container__7Kd1y",hidden:"Admin_hidden__blWKt",controls:"Admin_controls__RhTAv",input:"Admin_input__9_7r7",checkbox:"Admin_checkbox__Ttf_p"}},1163:function(e,t,n){e.exports=n(880)},6552:function(e,t,n){"use strict";n.d(t,{Kx:function(){return f},Xi:function(){return x}});var r=n(1294),u=n(7294),o=function(){return(o=Object.assign||function(e){for(var t,n=1,r=arguments.length;n<r;n++)for(var u in t=arguments[n])Object.prototype.hasOwnProperty.call(t,u)&&(e[u]=t[u]);return e}).apply(this,arguments)},i=function(e){return{loading:null==e,value:e}},s=function(e){var t=e?e():void 0,n=(0,u.useReducer)(function(e,t){switch(t.type){case"error":return o(o({},e),{error:t.error,loading:!1,value:void 0});case"reset":return i(t.defaultValue);case"value":return o(o({},e),{error:void 0,loading:!1,value:t.value});default:return e}},i(t)),r=n[0],s=n[1],c=(0,u.useCallback)(function(){s({type:"reset",defaultValue:e?e():void 0})},[e]),a=(0,u.useCallback)(function(e){s({type:"error",error:e})},[]),l=(0,u.useCallback)(function(e){s({type:"value",value:e})},[]);return(0,u.useMemo)(function(){return{error:r.error,loading:r.loading,reset:c,setError:a,setValue:l,value:r.value}},[r.error,r.loading,c,a,l,r.value])},c=function(e,t,n){var r=(0,u.useRef)(e);return(0,u.useEffect)(function(){!t(e,r.current)&&(r.current=e,n&&n())}),r},a=function(e,t){var n=!!e&&!!t&&(0,r.Eo)(e,t);return!e&&!t||n},l=function(e,t){var n=!!e&&!!t&&(0,r.iE)(e,t);return!e&&!t||n},f=function(e,t){var n=s(),o=n.error,i=n.loading,a=n.reset,f=n.setError,d=n.setValue,x=n.value,h=c(e,l,a);return(0,u.useEffect)(function(){if(!h.current){d(void 0);return}var e=(null==t?void 0:t.snapshotListenOptions)?(0,r.cf)(h.current,t.snapshotListenOptions,d,f):(0,r.cf)(h.current,d,f);return function(){e()}},[h.current]),[x,i,o]},d=function(e,t){var n=s(),o=n.error,i=n.loading,l=n.reset,f=n.setError,d=n.setValue,x=n.value,h=c(e,a,l);return(0,u.useEffect)(function(){if(!h.current){d(void 0);return}var e=(null==t?void 0:t.snapshotListenOptions)?(0,r.cf)(h.current,t.snapshotListenOptions,d,f):(0,r.cf)(h.current,d,f);return function(){e()}},[h.current]),[x,i,o]},x=function(e,t){var n=d(e,t),r=n[0],u=n[1],o=n[2];return[h(r,null==t?void 0:t.snapshotOptions,null==t?void 0:t.initialValue),u,o,r]},h=function(e,t,n){return(0,u.useMemo)(function(){var r;return null!==(r=null==e?void 0:e.data(t))&&void 0!==r?r:n},[e,t,n])}}},function(e){e.O(0,[774,888,179],function(){return e(e.s=8195)}),_N_E=e.O()}]);