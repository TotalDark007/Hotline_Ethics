(function(){
  function compareFactory(type){
    const statusOrder = { 'New': 1, 'Ongoing': 2, 'Resolved': 3 };
    return function(a,b){
      if(type==='num') return (parseFloat(a)||0)-(parseFloat(b)||0);
      if(type==='date') return (Date.parse(a.replace(' ','T'))||0)-(Date.parse(b.replace(' ','T'))||0);
      if(type==='status') return (statusOrder[a]||0)-(statusOrder[b]||0);
      return a.localeCompare(b, undefined, {sensitivity:'base'});
    };
  }
  function makeSortable(table){
    const ths = table.querySelectorAll('thead th.sortable');
    ths.forEach(function(th){
      th.style.cursor='pointer';
      th.addEventListener('click', function(){
        const idx = th.cellIndex;
        const type = th.getAttribute('data-type')||'text';
        const tbody = table.tBodies[0];
        const rows = Array.from(tbody.querySelectorAll('tr'));
        const asc = th.getAttribute('data-order')!=='desc';
        const getText = td => (td && td.textContent || '').trim();
        const cmp = compareFactory(type);
        rows.sort(function(r1,r2){
          const t1 = getText(r1.cells[idx]);
          const t2 = getText(r2.cells[idx]);
          const v = cmp(t1,t2);
          return asc ? v : -v;
        });
        ths.forEach(h=>h.removeAttribute('data-order'));
        th.setAttribute('data-order', asc?'desc':'asc');
        rows.forEach(r=>tbody.appendChild(r));
      });
    });
  }
  document.addEventListener('DOMContentLoaded', function(){
    document.querySelectorAll('table').forEach(makeSortable);
  });
})();
