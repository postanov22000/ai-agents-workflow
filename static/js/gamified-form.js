// static/js/gamified-form.js

function initGamifiedForm() {
  const missionCards = document.querySelectorAll('.mission-card');
  if (!missionCards.length) return;

  const btnPrev    = document.getElementById('btn-prev');
  const btnNext    = document.getElementById('btn-next');
  const progressFill = document.getElementById('progress-fill');
  const progressText = document.getElementById('progress-text');
  const achievementBadge = document.getElementById('achievement-badge');
  const confettiContainer = document.getElementById('confetti-container');

  let currentMission = 0;
  const totalMissions = missionCards.length;

  function updateProgress() {
    const pct = ((currentMission+1)/totalMissions)*100;
    progressFill.style.width = pct + '%';
    progressText.textContent = `${currentMission+1}/${totalMissions}`;
  }

  function updateButtonState() {
    btnPrev.style.visibility = currentMission===0 ? 'hidden' : 'visible';
    if (currentMission === totalMissions-1) {
      btnNext.textContent = '🚀 Launch Deal!';
      btnNext.classList.replace('btn-next','btn-submit');
    } else {
      btnNext.innerHTML = 'Next Mission <i class="fas fa-arrow-right"></i>';
      btnNext.classList.replace('btn-submit','btn-next');
    }
  }

  function createConfetti() {
    confettiContainer.innerHTML = '';
    for (let i=0; i<80; i++){
      const c = document.createElement('div');
      c.classList.add('confetti');
      const x = Math.random()*100+'%';
      const y = Math.random()*100+'%';
      const size = (Math.random()*6+4)+'px';
      const colors = ['#64ffda','#f72585','#ff9e00','#4361ee','#7209b7'];
      const clr = colors[Math.floor(Math.random()*colors.length)];
      const rot = Math.random()*360+'deg';
      c.style.left=x; c.style.top=y;
      c.style.width=size; c.style.height=size;
      c.style.backgroundColor=clr;
      if (Math.random()<0.5) c.style.borderRadius='50%';
      else if (Math.random()<0.5) c.style.clipPath='polygon(50% 0,0 100%,100% 100%)';
      c.style.transform=`rotate(${rot})`;
      const dur = (Math.random()*2+1)+'s';
      c.style.animation=`confettiFall ${dur} forwards`;
      confettiContainer.appendChild(c);
    }
  }

  const style = document.createElement('style');
  style.textContent = `
    @keyframes confettiFall {
      0% { opacity:1; transform: translateY(-100px) rotate(0deg); }
      100% { opacity:0; transform: translateY(100vh) rotate(360deg); }
    }
  `;
  document.head.appendChild(style);

  function showAchievement(msg='Mission Complete! 🎉') {
    achievementBadge.textContent = msg;
    achievementBadge.classList.add('show');
    createConfetti();
  }
  function hideAchievement() {
    achievementBadge.classList.remove('show');
  }

  function validateCurrent() {
    const reqs = missionCards[currentMission]
      .querySelectorAll('input[required], select[required], input[type="checkbox"][required]');
    for (let el of reqs) {
      if (el.type==='checkbox'? !el.checked : !el.value.trim()) {
        el.focus(); return false;
      }
    }
    return true;
  }

  btnNext.onclick = ()=>{
    if (currentMission < totalMissions-1) {
      if (!validateCurrent()) return alert('Complete required fields.');
      showAchievement();
      setTimeout(()=>{
        hideAchievement();
        missionCards[currentMission].classList.remove('active');
        currentMission++;
        missionCards[currentMission].classList.add('active');
        updateProgress(); updateButtonState();
        window.scrollTo({top:0,behavior:'smooth'});
      },800);
    } else {
      if (!validateCurrent()) return alert('Complete required fields.');
      showAchievement('Deal Complete! 🚀');
      setTimeout(()=>{
        document.getElementById('new-txn-form').submit();
      },1000);
    }
  };

  btnPrev.onclick = ()=>{
    if (currentMission>0) {
      missionCards[currentMission].classList.remove('active');
      currentMission--;
      missionCards[currentMission].classList.add('active');
      updateProgress(); updateButtonState();
      window.scrollTo({top:0,behavior:'smooth'});
    }
  };

  updateProgress();
  updateButtonState();
}

// initialize on page load
document.addEventListener('DOMContentLoaded', initGamifiedForm);
// re‑init after HTMX swap
document.body.addEventListener('htmx:afterSwap', evt => {
  if (evt.detail.target.closest('#new-txn-form')) {
    initGamifiedForm();
  }
});
