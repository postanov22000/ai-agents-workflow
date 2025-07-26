// static/js/gamified-form.js

window.initGamifiedForm = function(){
  const missionCards = document.querySelectorAll('.mission-card');
  const btnPrev       = document.getElementById('btn-prev');
  const btnNext       = document.getElementById('btn-next');
  const progressFill  = document.getElementById('progress-fill');
  const progressText  = document.getElementById('progress-text');
  const achievement   = document.getElementById('achievement-badge');
  const confettiWrap  = document.getElementById('confetti-container');
  let currentMission  = 0,
      totalMissions   = missionCards.length;

  function updateProgress(){
    const pct = ((currentMission+1)/totalMissions)*100;
    progressFill.style.width = pct+'%';
    progressText.textContent  = `${currentMission+1}/${totalMissions}`;
  }
  function updateButtons(){
    btnPrev.style.visibility = currentMission===0 ? 'hidden':'visible';
    if(currentMission===totalMissions-1){
      btnNext.textContent = '🚀 Launch Deal!';
      btnNext.classList.replace('btn-next','btn-submit');
    } else {
      btnNext.innerHTML = 'Next Mission <i class="fas fa-arrow-right"></i>';
      btnNext.classList.replace('btn-submit','btn-next');
    }
  }
  function showBadge(msg='Mission Complete! 🎉'){
    achievement.textContent = msg;
    achievement.classList.add('show');
    createConfetti();
  }
  function hideBadge(){ achievement.classList.remove('show'); }
  function createConfetti(){
    confettiWrap.innerHTML = '';
    for(let i=0;i<80;i++){
      const c=document.createElement('div');
      c.classList.add('confetti');
      const x= Math.random()*100+'%', y= Math.random()*100+'%';
      const size=(Math.random()*6+4)+'px';
      const colors=['#64ffda','#f72585','#ff9e00','#4361ee','#7209b7'];
      const clr=colors[Math.floor(Math.random()*colors.length)];
      const rot=Math.random()*360+'deg';
      c.style.cssText=`
        left:${x}; top:${y};
        width:${size}; height:${size};
        background-color:${clr};
        transform:rotate(${rot});
        animation:confettiFall ${Math.random()*2+1}s forwards;
      `;
      if(Math.random()<0.5) c.style.borderRadius='50%';
      else if(Math.random()<0.5) c.style.clipPath='polygon(50% 0,0 100%,100% 100%)';
      confettiWrap.appendChild(c);
    }
  }
  // inject confetti keyframes once
  if(!document.getElementById('confettiKeyframes')){
    const style=document.createElement('style');
    style.id='confettiKeyframes';
    style.textContent=`
      @keyframes confettiFall {
        0% { opacity:1; transform: translateY(-100px) rotate(0deg); }
        100% { opacity:0; transform: translateY(100vh) rotate(360deg); }
      }
    `;
    document.head.appendChild(style);
  }
  function validateMission(){
    const inputs = missionCards[currentMission]
      .querySelectorAll('input[required],select[required],input[type="checkbox"][required]');
    for(let el of inputs){
      if(el.type==='checkbox' ? !el.checked : !el.value.trim()){
        el.focus();
        return false;
      }
    }
    return true;
  }

  // wire buttons
  btnNext.onclick = ()=>{
    if(currentMission < totalMissions-1){
      if(!validateMission()) return alert('Please complete all required fields.');
      showBadge();
      setTimeout(()=>{
        hideBadge();
        missionCards[currentMission].classList.remove('active');
        currentMission++;
        missionCards[currentMission].classList.add('active');
        updateProgress(); updateButtons();
        window.scrollTo({top:0,behavior:'smooth'});
      },1000);
    } else {
    if (!validateMission()) return alert('Please complete all required fields.');
    showBadge('Deal Complete! 🚀');
    setTimeout(() => document.getElementById('new-txn-form').submit(), 1200);
  }
};
  btnPrev.onclick = ()=>{
    if(currentMission>0){
      missionCards[currentMission].classList.remove('active');
      currentMission--;
      missionCards[currentMission].classList.add('active');
      updateProgress(); updateButtons();
      window.scrollTo({top:0,behavior:'smooth'});
    }
  };

  // init state
  updateProgress();
  updateButtons();
};

// run on initial load
document.addEventListener('DOMContentLoaded', initGamifiedForm);
