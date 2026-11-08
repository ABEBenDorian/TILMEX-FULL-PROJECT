(() => {
  'use strict';
  const token=()=>localStorage.getItem('tilmex_token')||localStorage.getItem('token')||'';
  async function request(url,options={}){
    const headers={...(options.headers||{})};const t=token();if(t)headers.Authorization=`Bearer ${t}`;
    if(options.body && typeof options.body==='string')headers['Content-Type']='application/json';
    const response=await fetch(url,{...options,headers});const data=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(data.error||data.message||`Request failed (${response.status})`);return data;
  }
  const json=x=>JSON.stringify(x);
  window.TilMexSocial=Object.freeze({
    loadFeed:()=>request('/api/social/feed'),
    loadFavorites:()=>request('/api/social/favorites'),
    createPost:({caption='',mediaData=null}={})=>request('/api/social/posts',{method:'POST',body:json({caption,mediaData})}),
    reactToPost:(id,reaction)=>request(`/api/social/posts/${encodeURIComponent(id)}/reaction`,{method:'POST',body:json({reaction})}),
    getComments:id=>request(`/api/social/posts/${encodeURIComponent(id)}/comments`),
    addComment:(id,content)=>request(`/api/social/posts/${encodeURIComponent(id)}/comments`,{method:'POST',body:json({content})}),
    toggleFollow:id=>request(`/api/social/users/${encodeURIComponent(id)}/follow`,{method:'POST',body:'{}'}),
    getProfileStats:id=>request(`/api/social/users/${encodeURIComponent(id)}/stats`),
    toggleFavorite:id=>request(`/api/social/posts/${encodeURIComponent(id)}/favorite`,{method:'POST',body:'{}'}),
    updateProfile:payload=>request('/api/profile',{method:'PUT',body:json(payload)}),
    updateProfilePhoto:photo=>request('/api/profile/photo',{method:'PUT',body:json({photo})}),
    fileToDataUrl(file,maxMB=6){return new Promise((resolve,reject)=>{
      if(!file)return resolve(null);
      if(!/^(image\/(jpeg|png|gif|webp)|video\/(mp4|webm|quicktime)|audio\/(webm|ogg|mp4|mpeg|wav)(?:;codecs=[A-Za-z0-9._-]+)?)$/.test(file.type))return reject(new Error('Choose a supported image, video or audio file.'));
      if(file.size>maxMB*1024*1024)return reject(new Error(`Choose a file smaller than ${maxMB} MB.`));
      const reader=new FileReader();reader.onload=()=>resolve(String(reader.result));reader.onerror=()=>reject(new Error('Could not read this file.'));reader.readAsDataURL(file);
    });}
  });
})();
