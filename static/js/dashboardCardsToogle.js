const toggleSection = (sectionId) => {
  const sections = ['addUserSection', 'usersSection', 'card3Section'];

  sections.forEach((section) => {
    console.log(section);
    const element = document.querySelector(`#${section}`);
    const isOpen = section === sectionId;

    // Update the display style
    element.style.display = isOpen ? 'block' : 'none';
  });
};

// Function to initialize the section states
const initializeSectionStates = () => {
  // Set addUserSection to be displayed initially
  toggleSection('addUserSection');
};

// Call the initializeSectionStates function when the page loads
window.addEventListener('load', initializeSectionStates);

// Add click event listeners to the cards
document.getElementById('addUserCard').addEventListener('click', () => {
  toggleSection('addUserSection');
});

document.getElementById('card2').addEventListener('click', () => {
  toggleSection('usersSection');
});

document.getElementById('card3').addEventListener('click', () => {
  toggleSection('card3Section');
});

console.log('asdsa');
