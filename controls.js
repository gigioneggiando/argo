// Progressive enhancement: the native selects remain the form's source of truth.
window.ArgoControls = {
  enhance(form) {
    const controls = [];
    for (const select of form.querySelectorAll('select')) {
      const label = select.closest('label');
      const caption = label.firstChild.textContent.trim();
      const wrapper = document.createElement('div');
      wrapper.className = 'custom-select';
      const trigger = document.createElement('button');
      trigger.type = 'button';
      trigger.className = 'select-trigger';
      trigger.id = `${select.id}-trigger`;
      trigger.setAttribute('role', 'combobox');
      trigger.setAttribute('aria-label', caption);
      trigger.setAttribute('aria-haspopup', 'listbox');
      trigger.setAttribute('aria-expanded', 'false');
      trigger.setAttribute('aria-controls', `${select.id}-listbox`);
      const value = document.createElement('span');
      value.className = 'select-value';
      const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      arrow.setAttribute('viewBox', '0 0 16 16');
      arrow.setAttribute('width', '16');
      arrow.setAttribute('height', '16');
      arrow.setAttribute('aria-hidden', 'true');
      arrow.innerHTML = '<path d="m4 6 4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>';
      trigger.append(value, arrow);
      const list = document.createElement('ul');
      list.className = 'select-options';
      list.id = `${select.id}-listbox`;
      list.hidden = true;
      list.setAttribute('role', 'listbox');
      list.setAttribute('aria-label', caption);
      let active = select.selectedIndex;
      const items = [...select.options].map((option, index) => {
        const item = document.createElement('li');
        item.id = `${select.id}-option-${index}`;
        item.setAttribute('role', 'option');
        item.setAttribute('aria-selected', 'false');
        if (select.id === 'severityFilter' && option.value) item.dataset.severity = option.value;
        const name = document.createElement('span');
        name.textContent = option.text;
        const check = document.createElement('span');
        check.className = 'option-check';
        check.setAttribute('aria-hidden', 'true');
        check.textContent = '✓';
        item.append(name, check);
        item.addEventListener('mousedown', event => event.preventDefault());
        item.addEventListener('click', () => choose(index));
        list.append(item);
        return item;
      });
      function highlight(index) {
        active = (index + items.length) % items.length;
        items.forEach((item, i) => item.classList.toggle('active-option', i === active));
        trigger.setAttribute('aria-activedescendant', items[active].id);
        items[active].scrollIntoView({ block: 'nearest', behavior: 'instant' });
      }
      function close() {
        list.hidden = true;
        wrapper.classList.remove('is-open');
        trigger.setAttribute('aria-expanded', 'false');
        trigger.removeAttribute('aria-activedescendant');
      }
      function open() {
        controls.forEach(control => control.close());
        list.hidden = false;
        wrapper.classList.add('is-open');
        trigger.setAttribute('aria-expanded', 'true');
        highlight(select.selectedIndex);
      }
      function sync() {
        value.textContent = select.selectedOptions[0].text;
        trigger.title = `${caption}: ${value.textContent}`;
        if (select.id === 'severityFilter') trigger.dataset.severity = select.value;
        items.forEach((item, i) => item.setAttribute('aria-selected', String(i === select.selectedIndex)));
      }
      function choose(index) {
        select.selectedIndex = index;
        select.dispatchEvent(new Event('change', { bubbles: true }));
        sync(); close(); trigger.focus({ preventScroll: true });
      }
      let typed = '', typedAt = 0;
      trigger.addEventListener('click', () => list.hidden ? open() : close());
      trigger.addEventListener('keydown', event => {
        const key = event.key;
        if (['ArrowDown', 'ArrowUp', 'Home', 'End', 'Enter', ' ', 'Escape'].includes(key)) {
          event.preventDefault();
          if (key === 'Escape') { close(); return; }
          if (key === 'Enter' || key === ' ') { list.hidden ? open() : choose(active); return; }
          const wasClosed = list.hidden;
          if (wasClosed) open();
          if (key === 'Home') highlight(0);
          else if (key === 'End') highlight(items.length - 1);
          else highlight(active + (key === 'ArrowDown' ? 1 : -1));
        } else if (key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
          typed = Date.now() - typedAt > 600 ? key : typed + key;
          typedAt = Date.now();
          if (list.hidden) open();
          const index = [...select.options].findIndex(option => option.text.toLowerCase().startsWith(typed.toLowerCase()));
          if (index >= 0) highlight(index);
        }
      });
      wrapper.addEventListener('focusout', event => { if (!wrapper.contains(event.relatedTarget)) close(); });
      document.addEventListener('pointerdown', event => { if (!wrapper.contains(event.target)) close(); });
      // Avoid nesting an interactive popup inside the original native label.
      const field = document.createElement('div');
      field.className = 'filter-field';
      const fieldLabel = document.createElement('label');
      fieldLabel.htmlFor = trigger.id;
      fieldLabel.textContent = caption;
      label.replaceWith(field);
      select.hidden = true;
      wrapper.append(select, trigger, list);
      field.append(fieldLabel, wrapper);
      controls.push({ sync, close });
      sync();
    }
    return { sync: () => controls.forEach(control => control.sync()) };
  }
};
