//! Worklist scheduling for the fixpoints both backends iterate.
//!
//! Rusi reaches a fixpoint at two levels: inside a function, over its
//! control-flow graph, and across functions, over the call graph the
//! summaries follow. Neither level bounds how many rounds it runs. An item is
//! only marked dirty again when a join strictly grew its state, and every
//! state is drawn from a finite domain, so the iteration stops by itself. What
//! is left to decide is the order dirty items are revisited in, and that order
//! decides how much work reaching the fixpoint costs.
//!
//! [`MinRankWorklist`] is the "min-rank" traversal rustc adopted for its MIR
//! dataflow analyses (rust-lang/rust#160193). Every item has a rank in
//! dataflow order and the worklist always yields the lowest-ranked dirty item.
//! When a back edge dirties an earlier item the traversal returns to it at
//! once, instead of first running later items on input that is about to
//! change. Acyclic input is finished in one pass, each item evaluated once.
//!
//! rustc ranks blocks by reverse postorder. Reverse postorder alone can rank a
//! loop's exit, and everything after it, ahead of the loop body, depending on
//! the order a block lists its successors in; min-rank then walks the rest of
//! the function again on every trip around the loop. Rusi ranks blocks by a
//! weak topological order instead ([`weak_topological_order`], after
//! Bourdoncle 1993): every loop's blocks sit together right after its head, so
//! min-rank settles loops innermost first and reaches a loop's exit only once
//! the loop is stable, whatever the successor order.
//!
//! [`WaveWorklist`] is the same traversal batched for parallel evaluation over
//! a call graph ranked callees first ([`callee_first_order`]). It yields every
//! dirty item of the lowest dirty call-graph level together. Items on one
//! level never call each other outside their own recursion cycle, so a wave
//! can be evaluated concurrently.
//!
//! The call-graph clients learn what an evaluation depended on by recording
//! the summaries it read ([`TrackedReads`], [`Dependents`]), so a changed
//! summary re-dirties exactly the functions that looked at it.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const UNRANKED: usize = usize::MAX;
const WORD_BITS: usize = u64::BITS as usize;

/// A fixed-size set of small integers, with the one query the worklists need
/// beyond membership: the first member at or after a position.
#[derive(Debug, Clone)]
struct DenseBitSet {
    words: Vec<u64>,
    len: usize,
}

impl DenseBitSet {
    fn new_filled(len: usize) -> Self {
        let mut words = vec![u64::MAX; len.div_ceil(WORD_BITS)];
        let spare = words.len() * WORD_BITS - len;
        if spare > 0
            && let Some(last) = words.last_mut()
        {
            *last >>= spare;
        }
        Self { words, len }
    }

    fn insert(&mut self, index: usize) {
        debug_assert!(index < self.len);
        self.words[index / WORD_BITS] |= 1 << (index % WORD_BITS);
    }

    fn remove(&mut self, index: usize) {
        debug_assert!(index < self.len);
        self.words[index / WORD_BITS] &= !(1 << (index % WORD_BITS));
    }

    fn first_set_at_or_after(&self, index: usize) -> Option<usize> {
        if index >= self.len {
            return None;
        }
        let mut word_index = index / WORD_BITS;
        // Mask out the members below `index` in its own word.
        let mut word = self.words[word_index] & (u64::MAX << (index % WORD_BITS));
        loop {
            if word != 0 {
                return Some(word_index * WORD_BITS + word.trailing_zeros() as usize);
            }
            word_index += 1;
            word = *self.words.get(word_index)?;
        }
    }
}

/// Nodes reachable from `entry`, in reverse postorder.
///
/// This is dataflow order for a forward analysis: for every edge `a -> b` that
/// is not a back edge, `a` comes before `b`. Unreachable nodes are left out,
/// and successors outside `0..len` are ignored. The walk keeps its own stack,
/// so a very long chain of blocks cannot overflow the thread's.
pub fn reverse_postorder<I>(
    len: usize,
    entry: usize,
    mut successors: impl FnMut(usize) -> I,
) -> Vec<usize>
where
    I: IntoIterator<Item = usize>,
{
    if entry >= len {
        return Vec::new();
    }
    let mut visited = vec![false; len];
    let mut postorder = Vec::with_capacity(len);
    let mut stack: Vec<(usize, I::IntoIter)> = Vec::new();
    visited[entry] = true;
    stack.push((entry, successors(entry).into_iter()));
    while let Some((node, pending)) = stack.last_mut() {
        let node = *node;
        match pending.next() {
            Some(next) => {
                if next < len && !visited[next] {
                    visited[next] = true;
                    let next_successors = successors(next).into_iter();
                    stack.push((next, next_successors));
                }
            }
            None => {
                postorder.push(node);
                stack.pop();
            }
        }
    }
    postorder.reverse();
    postorder
}

/// Strongly connected components of `adjacency`, by Tarjan's algorithm with
/// an explicit stack. Returns each node's component and the component count.
/// Components are numbered in completion order, which is a reverse
/// topological order: a component's number is below those of every component
/// that reaches it.
fn strongly_connected_components(adjacency: &[Vec<usize>]) -> (Vec<usize>, usize) {
    const UNVISITED: usize = usize::MAX;
    let len = adjacency.len();
    let mut index = vec![UNVISITED; len];
    let mut lowlink = vec![0usize; len];
    let mut on_stack = vec![false; len];
    let mut component = vec![UNVISITED; len];
    let mut count = 0usize;
    let mut component_stack: Vec<usize> = Vec::new();
    let mut walk: Vec<(usize, usize)> = Vec::new();
    let mut next_index = 0usize;

    for root in 0..len {
        if index[root] != UNVISITED {
            continue;
        }
        index[root] = next_index;
        lowlink[root] = next_index;
        next_index += 1;
        component_stack.push(root);
        on_stack[root] = true;
        walk.push((root, 0));
        while let Some(&mut (node, ref mut edge)) = walk.last_mut() {
            if let Some(&next) = adjacency[node].get(*edge) {
                *edge += 1;
                if index[next] == UNVISITED {
                    index[next] = next_index;
                    lowlink[next] = next_index;
                    next_index += 1;
                    component_stack.push(next);
                    on_stack[next] = true;
                    walk.push((next, 0));
                } else if on_stack[next] {
                    lowlink[node] = lowlink[node].min(index[next]);
                }
                continue;
            }
            walk.pop();
            if let Some(&(parent, _)) = walk.last() {
                lowlink[parent] = lowlink[parent].min(lowlink[node]);
            }
            if lowlink[node] == index[node] {
                while let Some(member) = component_stack.pop() {
                    on_stack[member] = false;
                    component[member] = count;
                    if member == node {
                        break;
                    }
                }
                count += 1;
            }
        }
    }
    (component, count)
}

/// Nodes reachable from `entry` in a weak topological order (Bourdoncle,
/// "Efficient chaotic iteration strategies with widenings", 1993).
///
/// The order is a topological order of the strongly connected components,
/// and inside each component (a loop) it lists the component's head first,
/// then the rest of the component ordered the same way with the head removed.
/// Every loop therefore occupies one contiguous run starting at its head, and
/// nested loops occupy runs inside it. For every edge `a -> b` that does not
/// enter a loop head from inside that loop, `a` comes before `b`.
///
/// A loop's head is its first block in reverse postorder: the block the loop
/// is entered through, and for an irreducible loop one of its entries.
/// Successors outside `0..len` are ignored; each nesting level of loops costs
/// one more linear pass over that loop's blocks.
pub fn weak_topological_order<I>(
    len: usize,
    entry: usize,
    mut successors: impl FnMut(usize) -> I,
) -> Vec<usize>
where
    I: IntoIterator<Item = usize>,
{
    enum Task {
        Emit(usize),
        Order(Vec<usize>),
    }

    let adjacency: Vec<Vec<usize>> = (0..len)
        .map(|node| {
            successors(node)
                .into_iter()
                .filter(|next| *next < len)
                .collect()
        })
        .collect();
    let reachable = reverse_postorder(len, entry, |node| adjacency[node].iter().copied());
    let mut order = Vec::with_capacity(reachable.len());
    let mut local = vec![UNRANKED; len];
    let mut tasks = vec![Task::Order(reachable)];
    while let Some(task) = tasks.pop() {
        let nodes = match task {
            Task::Emit(node) => {
                order.push(node);
                continue;
            }
            Task::Order(nodes) => nodes,
        };
        // `nodes` is in reverse postorder, and so is each component carved
        // out of it below, so a component's first node is its head.
        for (position, node) in nodes.iter().enumerate() {
            local[*node] = position;
        }
        let induced: Vec<Vec<usize>> = nodes
            .iter()
            .map(|node| {
                adjacency[*node]
                    .iter()
                    .map(|next| local[*next])
                    .filter(|position| *position != UNRANKED)
                    .collect()
            })
            .collect();
        for node in &nodes {
            local[*node] = UNRANKED;
        }
        let (component, count) = strongly_connected_components(&induced);
        let mut members: Vec<Vec<usize>> = vec![Vec::new(); count];
        for (position, node) in nodes.iter().enumerate() {
            members[component[position]].push(*node);
        }
        // Components are numbered sinks first. Pushing them in that order
        // leaves the topologically first component on top of the stack.
        for mut component_nodes in members {
            let head = component_nodes[0];
            let cyclic = component_nodes.len() > 1 || adjacency[head].contains(&head);
            if cyclic && component_nodes.len() > 1 {
                component_nodes.remove(0);
                tasks.push(Task::Order(component_nodes));
            }
            tasks.push(Task::Emit(head));
        }
    }
    order
}

/// Min-rank worklist (rust-lang/rust#160193).
///
/// Every item in `order` starts dirty. [`MinRankWorklist::pop`] yields the
/// lowest-ranked dirty item and marks it clean; [`MinRankWorklist::mark_dirty`]
/// marks an item dirty again, and when that item ranks at or before the one
/// just yielded, the next `pop` returns to it. Each item is therefore only
/// evaluated after all of its dirty predecessors in `order`, ignoring back
/// edges, and loop-free input is finished in a single pass.
#[derive(Debug, Clone)]
pub struct MinRankWorklist {
    order: Vec<usize>,
    rank: Vec<usize>,
    dirty: DenseBitSet,
    cursor: usize,
    evaluations: usize,
}

impl MinRankWorklist {
    /// A worklist over items `0..len`, ranked by their position in `order`.
    /// Items missing from `order` are never yielded and cannot be dirtied.
    ///
    /// # Panics
    ///
    /// When `order` names an item outside `0..len` or names one twice.
    pub fn new(len: usize, order: Vec<usize>) -> Self {
        let mut rank = vec![UNRANKED; len];
        for (position, &item) in order.iter().enumerate() {
            assert!(item < len, "item {item} is outside 0..{len}");
            assert_eq!(rank[item], UNRANKED, "item {item} is ranked twice");
            rank[item] = position;
        }
        let dirty = DenseBitSet::new_filled(order.len());
        Self {
            order,
            rank,
            dirty,
            cursor: 0,
            evaluations: 0,
        }
    }

    /// The lowest-ranked dirty item, now marked clean.
    #[allow(clippy::should_implement_trait)]
    pub fn pop(&mut self) -> Option<usize> {
        let position = self.dirty.first_set_at_or_after(self.cursor)?;
        self.dirty.remove(position);
        self.cursor = position;
        self.evaluations += 1;
        Some(self.order[position])
    }

    /// Marks `item` dirty. Returns false, and does nothing, for an item that
    /// has no rank: an unreachable block or an index outside the worklist.
    pub fn mark_dirty(&mut self, item: usize) -> bool {
        let Some(&position) = self.rank.get(item) else {
            return false;
        };
        if position == UNRANKED {
            return false;
        }
        self.dirty.insert(position);
        self.cursor = self.cursor.min(position);
        true
    }

    /// The position of `item` in dataflow order, if it has one.
    pub fn rank(&self, item: usize) -> Option<usize> {
        self.rank
            .get(item)
            .copied()
            .filter(|position| *position != UNRANKED)
    }

    /// The items in dataflow order.
    pub fn order(&self) -> &[usize] {
        &self.order
    }

    /// How many items have been yielded so far: the work the fixpoint took.
    pub fn evaluations(&self) -> usize {
        self.evaluations
    }
}

/// A call graph's items in callee-first order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallOrder {
    /// Every item, callees before their callers except inside a recursion
    /// cycle. Level-major: all level-0 items come first, then level 1, and so
    /// on; a cycle's members are adjacent.
    pub order: Vec<usize>,
    /// Each item's level. An item whose cycle calls nothing outside itself is
    /// on level 0; any other is one above the highest level it calls into.
    pub level: Vec<usize>,
    /// Each item's strongly connected component, numbered callees first.
    pub component: Vec<usize>,
}

/// Orders a call graph callees first, using Tarjan's strongly connected
/// components algorithm with an explicit stack.
///
/// `callees(item)` lists what `item` calls; entries outside `0..len` are
/// ignored. Recursion (a component with more than one member, or a
/// self-call) is kept together. The result depends only on the graph and on
/// item numbering, never on hashing, so it is the same on every run.
pub fn callee_first_order<I>(len: usize, mut callees: impl FnMut(usize) -> I) -> CallOrder
where
    I: IntoIterator<Item = usize>,
{
    let adjacency: Vec<Vec<usize>> = (0..len)
        .map(|item| {
            callees(item)
                .into_iter()
                .filter(|callee| *callee < len)
                .collect()
        })
        .collect();

    let (component, count) = strongly_connected_components(&adjacency);
    let mut components: Vec<Vec<usize>> = vec![Vec::new(); count];
    for (item, id) in component.iter().enumerate() {
        components[*id].push(item);
    }

    // Components are numbered in completion order, which already puts
    // callees first.
    let mut component_level = vec![0usize; components.len()];
    for (id, members) in components.iter().enumerate() {
        let level = members
            .iter()
            .flat_map(|member| &adjacency[*member])
            .map(|callee| component[*callee])
            .filter(|callee_component| *callee_component != id)
            .map(|callee_component| component_level[callee_component] + 1)
            .max()
            .unwrap_or(0);
        component_level[id] = level;
    }
    let level: Vec<usize> = (0..len)
        .map(|item| component_level[component[item]])
        .collect();
    let mut order: Vec<usize> = (0..len).collect();
    order.sort_by_key(|item| (level[*item], component[*item], *item));
    CallOrder {
        order,
        level,
        component,
    }
}

/// [`MinRankWorklist`] over a [`CallOrder`], yielding whole levels at a time.
///
/// [`WaveWorklist::pop_wave`] returns every dirty item on the lowest dirty
/// level, in callee-first order, and marks them clean. Callers of a changed
/// summary sit on a higher level, so they wait for a later wave; a summary
/// that changed inside a recursion cycle re-dirties members on its own level,
/// so that level is repeated until the cycle settles.
#[derive(Debug, Clone)]
pub struct WaveWorklist {
    inner: MinRankWorklist,
    level_by_position: Vec<usize>,
}

impl WaveWorklist {
    pub fn new(call_order: &CallOrder) -> Self {
        let level_by_position = call_order
            .order
            .iter()
            .map(|item| call_order.level[*item])
            .collect();
        Self {
            inner: MinRankWorklist::new(call_order.level.len(), call_order.order.clone()),
            level_by_position,
        }
    }

    /// Every dirty item on the lowest dirty level, now marked clean.
    pub fn pop_wave(&mut self) -> Option<Vec<usize>> {
        let first = self.inner.dirty.first_set_at_or_after(self.inner.cursor)?;
        let level = self.level_by_position[first];
        let mut wave = Vec::new();
        let mut position = first;
        while let Some(next) = self.inner.dirty.first_set_at_or_after(position) {
            if self.level_by_position[next] != level {
                break;
            }
            self.inner.dirty.remove(next);
            wave.push(self.inner.order[next]);
            position = next + 1;
        }
        self.inner.cursor = first;
        self.inner.evaluations += wave.len();
        Some(wave)
    }

    /// Marks `item` dirty; see [`MinRankWorklist::mark_dirty`].
    pub fn mark_dirty(&mut self, item: usize) -> bool {
        self.inner.mark_dirty(item)
    }

    /// How many items have been yielded so far.
    pub fn evaluations(&self) -> usize {
        self.inner.evaluations
    }
}

/// Which items each item read during its latest evaluation, kept in both
/// directions so a changed item finds its readers.
#[derive(Debug, Clone, Default)]
pub struct Dependents {
    readers: Vec<BTreeSet<usize>>,
    reads: Vec<Vec<usize>>,
}

impl Dependents {
    pub fn new(len: usize) -> Self {
        Self {
            readers: vec![BTreeSet::new(); len],
            reads: vec![Vec::new(); len],
        }
    }

    /// Replaces what `reader` read with `reads`. Indexes outside the table
    /// are ignored.
    pub fn record(&mut self, reader: usize, reads: impl IntoIterator<Item = usize>) {
        let len = self.readers.len();
        if reader >= len {
            return;
        }
        for previous in std::mem::take(&mut self.reads[reader]) {
            self.readers[previous].remove(&reader);
        }
        let mut current: Vec<usize> = reads.into_iter().filter(|read| *read < len).collect();
        current.sort_unstable();
        current.dedup();
        for read in &current {
            self.readers[*read].insert(reader);
        }
        self.reads[reader] = current;
    }

    /// The items whose latest evaluation read `item`, in index order.
    pub fn readers(&self, item: usize) -> impl Iterator<Item = usize> + '_ {
        self.readers
            .get(item)
            .into_iter()
            .flat_map(|readers| readers.iter().copied())
    }
}

/// A read-only view of a keyed table that remembers which rows one
/// evaluation looked up, by their index in `index`.
///
/// A view belongs to a single evaluation on a single thread; the table it
/// borrows can be shared between threads.
pub struct TrackedReads<'a, V> {
    table: &'a BTreeMap<String, V>,
    index: &'a HashMap<String, usize>,
    reads: RefCell<Vec<usize>>,
}

impl<'a, V> TrackedReads<'a, V> {
    pub fn new(table: &'a BTreeMap<String, V>, index: &'a HashMap<String, usize>) -> Self {
        Self {
            table,
            index,
            reads: RefCell::new(Vec::new()),
        }
    }

    /// Looks `key` up, recording the read when `key` is a tracked row.
    pub fn get(&self, key: &str) -> Option<&'a V> {
        if let Some(position) = self.index.get(key) {
            self.reads.borrow_mut().push(*position);
        }
        self.table.get(key)
    }

    /// The rows read so far, possibly with repeats.
    pub fn into_reads(self) -> Vec<usize> {
        self.reads.into_inner()
    }
}

/// Read access to a keyed table, served both by the table itself and by a
/// [`TrackedReads`] view of it, so one evaluation routine can run inside a
/// fixpoint (which records what it read) and after it (which does not).
pub trait KeyedTable<V> {
    fn lookup(&self, key: &str) -> Option<&V>;
}

impl<V> KeyedTable<V> for BTreeMap<String, V> {
    fn lookup(&self, key: &str) -> Option<&V> {
        self.get(key)
    }
}

impl<V> KeyedTable<V> for TrackedReads<'_, V> {
    fn lookup(&self, key: &str) -> Option<&V> {
        self.get(key)
    }
}

/// Unions `incoming` into `target`; true when `target` grew.
pub fn join_set<T: Ord>(target: &mut BTreeSet<T>, incoming: BTreeSet<T>) -> bool {
    let before = target.len();
    target.extend(incoming);
    target.len() != before
}

/// Unions `incoming` into `target` key by key; true when a key was added or
/// a key's set grew.
pub fn join_map<K: Ord, V: Ord>(
    target: &mut BTreeMap<K, BTreeSet<V>>,
    incoming: BTreeMap<K, BTreeSet<V>>,
) -> bool {
    let mut changed = false;
    for (key, values) in incoming {
        match target.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(values);
                changed = true;
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                changed |= join_set(entry.get_mut(), values);
            }
        }
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A small deterministic generator, so graph-shaped property tests need
    /// no dependency and replay identically.
    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0 >> 33
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    fn random_graph(rng: &mut Lcg, nodes: usize, extra_edges: usize) -> Vec<Vec<usize>> {
        let mut graph = vec![Vec::new(); nodes];
        // A spine keeps most nodes reachable from 0; the extra edges add
        // branches, back edges, self-loops and irreducible entries.
        for node in 1..nodes {
            let from = rng.below(node);
            graph[from].push(node);
        }
        for _ in 0..extra_edges {
            let from = rng.below(nodes);
            let to = rng.below(nodes);
            graph[from].push(to);
        }
        graph
    }

    /// Forward "which nodes can reach me" analysis: every node generates its
    /// own id and the join is set union. The fixpoint is independent of
    /// traversal order, so any two correct solvers must agree on it.
    fn solve_min_rank(graph: &[Vec<usize>]) -> (Vec<BTreeSet<usize>>, usize) {
        let order = weak_topological_order(graph.len(), 0, |node| graph[node].iter().copied());
        let mut entry: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); graph.len()];
        let mut worklist = MinRankWorklist::new(graph.len(), order);
        while let Some(node) = worklist.pop() {
            let mut out = entry[node].clone();
            out.insert(node);
            for &successor in &graph[node] {
                let before = entry[successor].len();
                entry[successor].extend(out.iter().copied());
                if entry[successor].len() != before {
                    worklist.mark_dirty(successor);
                }
            }
        }
        (entry, worklist.evaluations())
    }

    /// The traversal rusi used before: whole passes over every reachable
    /// block in index order until a pass changes nothing.
    fn solve_round_robin(graph: &[Vec<usize>]) -> (Vec<BTreeSet<usize>>, usize) {
        let reachable: BTreeSet<usize> =
            reverse_postorder(graph.len(), 0, |node| graph[node].iter().copied())
                .into_iter()
                .collect();
        let mut entry: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); graph.len()];
        let mut evaluations = 0;
        let mut changed = true;
        while changed {
            changed = false;
            for &node in &reachable {
                evaluations += 1;
                let mut out = entry[node].clone();
                out.insert(node);
                for &successor in &graph[node] {
                    let before = entry[successor].len();
                    entry[successor].extend(out.iter().copied());
                    changed |= entry[successor].len() != before;
                }
            }
        }
        (entry, evaluations)
    }

    /// The FIFO worklist rustc used before #160193, seeded in reverse
    /// postorder, re-dirtied blocks queued at the back.
    fn solve_fifo(graph: &[Vec<usize>]) -> (Vec<BTreeSet<usize>>, usize) {
        let order = reverse_postorder(graph.len(), 0, |node| graph[node].iter().copied());
        let mut queued = vec![false; graph.len()];
        let mut queue = VecDeque::new();
        for &node in &order {
            queued[node] = true;
            queue.push_back(node);
        }
        let mut entry: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); graph.len()];
        let mut evaluations = 0;
        while let Some(node) = queue.pop_front() {
            queued[node] = false;
            evaluations += 1;
            let mut out = entry[node].clone();
            out.insert(node);
            for &successor in &graph[node] {
                let before = entry[successor].len();
                entry[successor].extend(out.iter().copied());
                if entry[successor].len() != before && !queued[successor] {
                    queued[successor] = true;
                    queue.push_back(successor);
                }
            }
        }
        (entry, evaluations)
    }

    #[test]
    fn bitset_finds_first_member_across_words() {
        let mut set = DenseBitSet::new_filled(200);
        for index in 0..200 {
            set.remove(index);
        }
        assert_eq!(set.first_set_at_or_after(0), None);
        set.insert(3);
        set.insert(64);
        set.insert(199);
        assert_eq!(set.first_set_at_or_after(0), Some(3));
        assert_eq!(set.first_set_at_or_after(3), Some(3));
        assert_eq!(set.first_set_at_or_after(4), Some(64));
        assert_eq!(set.first_set_at_or_after(65), Some(199));
        assert_eq!(set.first_set_at_or_after(200), None);
        // The spare bits of the last word start clear.
        let filled = DenseBitSet::new_filled(65);
        assert_eq!(filled.first_set_at_or_after(64), Some(64));
        assert_eq!(filled.first_set_at_or_after(65), None);
        assert_eq!(filled.words[1], 1);
    }

    #[test]
    fn reverse_postorder_orders_forward_edges_and_drops_unreachable() {
        // 0 -> 1 -> 3, 0 -> 2 -> 3, 3 -> 1 (back edge), 4 unreachable,
        // 7 is an out-of-range successor.
        let graph = [vec![1, 2], vec![3], vec![3, 7], vec![1], vec![0]];
        let order = reverse_postorder(graph.len(), 0, |node| graph[node].iter().copied());
        assert_eq!(order.len(), 4);
        assert_eq!(order[0], 0);
        let position = |node| order.iter().position(|n| *n == node).unwrap();
        assert!(position(1) < position(3));
        assert!(position(2) < position(3));
        assert!(!order.contains(&4));
        assert!(reverse_postorder(0, 0, |_| Vec::new()).is_empty());
    }

    #[test]
    fn reverse_postorder_walks_a_long_chain_without_recursion() {
        let len = 200_000;
        let order = reverse_postorder(len, 0, |node| (node + 1 < len).then_some(node + 1));
        assert_eq!(order.len(), len);
        assert!(order.iter().enumerate().all(|(i, node)| i == *node));
    }

    #[test]
    fn loop_free_input_is_finished_in_one_pass_whatever_the_numbering() {
        // A diamond lattice numbered backwards, so index order is the reverse
        // of dataflow order: the old round-robin needed a pass per level.
        let width = 30;
        let depth = 40;
        let len = width * depth + 1;
        let label = |layer: usize, column: usize| len - 2 - (layer * width + column);
        let mut graph = vec![Vec::new(); len];
        for column in 0..width {
            graph[len - 1].push(label(0, column));
        }
        for layer in 0..depth - 1 {
            for column in 0..width {
                graph[label(layer, column)].push(label(layer + 1, column));
                graph[label(layer, column)].push(label(layer + 1, (column + 1) % width));
            }
        }
        let root = len - 1;
        let order = weak_topological_order(len, root, |node| graph[node].iter().copied());
        let mut worklist = MinRankWorklist::new(len, order);
        let mut seen = 0;
        while let Some(node) = worklist.pop() {
            seen += 1;
            for &successor in &graph[node] {
                // Mark everything a changed state would reach: still one
                // evaluation each, because successors rank later.
                assert!(worklist.mark_dirty(successor));
            }
        }
        assert_eq!(seen, len);
        assert_eq!(worklist.evaluations(), len);
    }

    #[test]
    fn min_rank_matches_the_reference_solvers_on_random_graphs() {
        // Random graphs are mostly irreducible and dense with back edges; on
        // them min-rank is not always the cheapest traversal, but it always
        // reaches the same fixpoint.
        let mut rng = Lcg(0x5eed);
        for case in 0..300 {
            let nodes = 1 + rng.below(60);
            let extra = rng.below(nodes * 2 + 1);
            let graph = random_graph(&mut rng, nodes, extra);
            let (min_rank, _) = solve_min_rank(&graph);
            let (round_robin, _) = solve_round_robin(&graph);
            let (fifo, _) = solve_fifo(&graph);
            assert_eq!(min_rank, round_robin, "case {case}: {graph:?}");
            assert_eq!(min_rank, fifo, "case {case}: {graph:?}");
        }
    }

    /// The shape behind rustc's cranelift-codegen numbers: one long function
    /// made of many loops in sequence. The FIFO queue and the old whole-pass
    /// traversal both run everything after a loop on the loop's unsettled
    /// output and then again for every later change; min-rank settles each
    /// loop before moving past it. Each head lists its body before its exit,
    /// the successor order under which reverse postorder ranks the exit (and
    /// the whole rest of the function) ahead of the body.
    #[test]
    fn a_sequence_of_loops_costs_min_rank_far_less() {
        let loops = 24;
        let body = 12;
        let mut graph: Vec<Vec<usize>> = vec![Vec::new()];
        let mut tail = 0;
        for _ in 0..loops {
            let head = graph.len();
            graph.push(Vec::new());
            graph[tail].push(head);
            let mut last = head;
            for _ in 0..body {
                let block = graph.len();
                graph.push(Vec::new());
                graph[last].push(block);
                last = block;
            }
            graph[last].push(head);
            let exit = graph.len();
            graph.push(Vec::new());
            graph[head].push(exit);
            tail = exit;
        }
        let blocks = graph.len();
        let (min_rank, min_rank_work) = solve_min_rank(&graph);
        let (fifo, fifo_work) = solve_fifo(&graph);
        let (round_robin, round_robin_work) = solve_round_robin(&graph);
        assert_eq!(min_rank, fifo);
        assert_eq!(min_rank, round_robin);
        // Each loop is walked twice (the second trip carries the back edge's
        // state through the body) and every block outside a loop once.
        assert_eq!(min_rank_work, blocks + loops * (body + 1));
        assert!(
            min_rank_work * 4 <= fifo_work,
            "min-rank {min_rank_work} vs fifo {fifo_work}"
        );
        // The old traversal needs a pass per trip plus one to see nothing
        // changed; with blocks numbered in dataflow order that is 3 passes.
        assert_eq!(round_robin_work, blocks * 3);
    }

    /// Nested loops, each head listing its exit first and its body second,
    /// and the reverse: the weak topological order is the same either way,
    /// so the work is too. A deep nest where every block adds a fact is the
    /// hard case for min-rank, which re-settles each inner loop on every trip
    /// around the outer one; it still beats the old whole-pass traversal,
    /// and lands close to FIFO.
    #[test]
    fn nested_loops_cost_the_same_whatever_the_successor_order() {
        fn nest(
            graph: &mut Vec<Vec<usize>>,
            level: usize,
            depth: usize,
            exit_first: bool,
        ) -> (usize, usize) {
            let head = graph.len();
            graph.push(Vec::new());
            let mut tail = head;
            let mut first_body = None;
            if level + 1 < depth {
                let (inner_head, inner_exit) = nest(graph, level + 1, depth, exit_first);
                first_body = Some(inner_head);
                graph[tail].push(inner_head);
                tail = inner_exit;
            }
            for _ in 0..6 {
                let block = graph.len();
                graph.push(Vec::new());
                first_body.get_or_insert(block);
                graph[tail].push(block);
                tail = block;
            }
            graph[tail].push(head);
            let exit = graph.len();
            graph.push(Vec::new());
            if exit_first {
                graph[head].insert(0, exit);
            } else {
                graph[head].push(exit);
            }
            (head, exit)
        }
        let mut work = Vec::new();
        for exit_first in [false, true] {
            let mut graph: Vec<Vec<usize>> = Vec::new();
            nest(&mut graph, 0, 6, exit_first);
            let (min_rank, min_rank_work) = solve_min_rank(&graph);
            let (fifo, fifo_work) = solve_fifo(&graph);
            let (round_robin, round_robin_work) = solve_round_robin(&graph);
            assert_eq!(min_rank, fifo);
            assert_eq!(min_rank, round_robin);
            assert!(
                min_rank_work < round_robin_work && min_rank_work * 4 < fifo_work * 5,
                "exit_first={exit_first}: min-rank {min_rank_work}, fifo {fifo_work}, round-robin {round_robin_work}"
            );
            work.push(min_rank_work);
        }
        assert_eq!(work[0], work[1]);
    }

    #[test]
    fn weak_topological_order_keeps_every_loop_contiguous_after_its_head() {
        let mut rng = Lcg(7);
        for case in 0..300 {
            let nodes = 1 + rng.below(60);
            let extra = rng.below(nodes * 2 + 1);
            let graph = random_graph(&mut rng, nodes, extra);
            let order = weak_topological_order(nodes, 0, |node| graph[node].iter().copied());
            let reachable = reverse_postorder(nodes, 0, |node| graph[node].iter().copied());
            let mut sorted = order.clone();
            sorted.sort_unstable();
            let mut expected = reachable.clone();
            expected.sort_unstable();
            assert_eq!(
                sorted, expected,
                "case {case}: a permutation of the reachable nodes"
            );
            // Every strongly connected component of the reachable graph is
            // one contiguous run of the order.
            let mut position = vec![usize::MAX; nodes];
            for (index, node) in order.iter().enumerate() {
                position[*node] = index;
            }
            let induced: Vec<Vec<usize>> = (0..nodes)
                .map(|node| {
                    if position[node] == usize::MAX {
                        Vec::new()
                    } else {
                        graph[node].clone()
                    }
                })
                .collect();
            let (component, count) = strongly_connected_components(&induced);
            for id in 0..count {
                let mut spots: Vec<usize> = reachable
                    .iter()
                    .filter(|node| component[**node] == id)
                    .map(|node| position[*node])
                    .collect();
                spots.sort_unstable();
                if let (Some(first), Some(last)) = (spots.first(), spots.last()) {
                    assert_eq!(
                        last - first + 1,
                        spots.len(),
                        "case {case}: component {id} split"
                    );
                }
            }
            // Edges between components always point forward.
            for &node in &reachable {
                for &next in &graph[node] {
                    if component[node] != component[next] {
                        assert!(
                            position[node] < position[next],
                            "case {case}: {node} -> {next}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn weak_topological_order_is_topological_on_acyclic_graphs() {
        let mut rng = Lcg(11);
        for case in 0..200 {
            let nodes = 1 + rng.below(80);
            let mut graph = vec![Vec::new(); nodes];
            for (from, successors) in graph.iter_mut().enumerate() {
                for _ in 0..rng.below(4) {
                    let to = from + 1 + rng.below(nodes - from);
                    if to < nodes {
                        successors.push(to);
                    }
                }
            }
            let order = weak_topological_order(nodes, 0, |node| graph[node].iter().copied());
            let mut position = vec![usize::MAX; nodes];
            for (index, node) in order.iter().enumerate() {
                position[*node] = index;
            }
            for &node in &order {
                for &next in &graph[node] {
                    assert!(position[node] < position[next], "case {case}");
                }
            }
        }
    }

    #[test]
    fn weak_topological_order_heads_nested_loops_before_their_bodies() {
        // 0 -> 1 (outer head) -> 2 (inner head) -> 3 -> 2, 3 -> 4 -> 1,
        // 1 -> 5 (exit). The outer head lists its exit first.
        let graph = [vec![1], vec![5, 2], vec![3], vec![2, 4], vec![1], vec![]];
        let order = weak_topological_order(graph.len(), 0, |node| graph[node].iter().copied());
        assert_eq!(order, vec![0, 1, 2, 3, 4, 5]);
        // A self-loop is its own component; an out-of-range successor is
        // ignored.
        let graph = [vec![1, 9], vec![1, 2], vec![]];
        assert_eq!(
            weak_topological_order(graph.len(), 0, |node| graph[node].iter().copied()),
            vec![0, 1, 2]
        );
        assert!(weak_topological_order(0, 0, |_| Vec::new()).is_empty());
    }

    #[test]
    fn weak_topological_order_handles_a_deep_loop_nest_without_recursion() {
        // 2000 nested self-contained loops: i -> i + 1 and i + 1 -> i.
        let len = 2_000;
        let order = weak_topological_order(len, 0, |node| {
            let mut next = Vec::new();
            if node + 1 < len {
                next.push(node + 1);
            }
            if node > 0 {
                next.push(node - 1);
            }
            next
        });
        assert_eq!(order, (0..len).collect::<Vec<_>>());
    }

    #[test]
    fn a_back_edge_returns_to_the_dirtied_loop_head() {
        // 0 -> 1 -> 2 -> 3, with 2 -> 1.
        let mut worklist = MinRankWorklist::new(4, vec![0, 1, 2, 3]);
        assert_eq!(worklist.pop(), Some(0));
        assert_eq!(worklist.pop(), Some(1));
        assert_eq!(worklist.pop(), Some(2));
        assert!(worklist.mark_dirty(1));
        assert_eq!(worklist.pop(), Some(1), "back to the head before 3");
        assert!(worklist.mark_dirty(2));
        assert_eq!(worklist.pop(), Some(2));
        assert_eq!(worklist.pop(), Some(3));
        assert_eq!(worklist.pop(), None);
        // A self-loop is re-evaluated at once.
        let mut worklist = MinRankWorklist::new(2, vec![0, 1]);
        assert_eq!(worklist.pop(), Some(0));
        worklist.mark_dirty(0);
        assert_eq!(worklist.pop(), Some(0));
        assert_eq!(worklist.pop(), Some(1));
        assert_eq!(worklist.evaluations(), 3);
    }

    #[test]
    fn unranked_items_are_never_dirtied() {
        let mut worklist = MinRankWorklist::new(3, vec![2, 0]);
        assert!(!worklist.mark_dirty(1));
        assert!(!worklist.mark_dirty(9));
        assert_eq!(worklist.rank(2), Some(0));
        assert_eq!(worklist.rank(1), None);
        assert_eq!(worklist.order(), &[2, 0]);
        assert_eq!(worklist.pop(), Some(2));
        assert_eq!(worklist.pop(), Some(0));
        assert_eq!(worklist.pop(), None);
    }

    #[test]
    #[should_panic(expected = "ranked twice")]
    fn a_duplicate_rank_is_rejected() {
        MinRankWorklist::new(2, vec![1, 1]);
    }

    #[test]
    fn callee_first_order_keeps_callees_ahead_and_cycles_together() {
        // 0 calls 1 and 2; 1 and 2 call each other; 2 calls 3; 3 calls
        // itself; 4 calls nothing and nobody calls it.
        let graph = [vec![1, 2], vec![2], vec![1, 3], vec![3], vec![]];
        let order = callee_first_order(graph.len(), |item| graph[item].iter().copied());
        assert_eq!(order.level, vec![2, 1, 1, 0, 0]);
        assert_eq!(order.component[1], order.component[2]);
        assert_ne!(order.component[0], order.component[1]);
        assert_eq!(order.order, vec![3, 4, 1, 2, 0]);
    }

    #[test]
    fn callee_first_order_holds_on_random_graphs() {
        let mut rng = Lcg(42);
        for case in 0..300 {
            let nodes = 1 + rng.below(50);
            let extra = rng.below(nodes * 2 + 1);
            let graph = random_graph(&mut rng, nodes, extra);
            let order = callee_first_order(nodes, |item| graph[item].iter().copied());
            let mut position = vec![0; nodes];
            for (index, item) in order.order.iter().enumerate() {
                position[*item] = index;
            }
            let mut sorted = order.order.clone();
            sorted.sort_unstable();
            assert_eq!(sorted, (0..nodes).collect::<Vec<_>>(), "case {case}");
            for (caller, callees) in graph.iter().enumerate() {
                for &callee in callees {
                    if order.component[caller] == order.component[callee] {
                        assert_eq!(order.level[caller], order.level[callee], "case {case}");
                    } else {
                        assert!(position[callee] < position[caller], "case {case}");
                        assert!(order.level[callee] < order.level[caller], "case {case}");
                    }
                }
            }
            // A component's members are adjacent in the order.
            for window in order.order.windows(3) {
                if order.component[window[0]] == order.component[window[2]] {
                    assert_eq!(order.component[window[0]], order.component[window[1]]);
                }
            }
            // Mutually reachable items share a component, and only they do.
            let reach = |from: usize| {
                reverse_postorder(nodes, from, |item| graph[item].iter().copied())
                    .into_iter()
                    .collect::<BTreeSet<_>>()
            };
            let reaches: Vec<_> = (0..nodes).map(reach).collect();
            for a in 0..nodes {
                for b in 0..nodes {
                    let mutual = reaches[a].contains(&b) && reaches[b].contains(&a);
                    assert_eq!(
                        mutual,
                        order.component[a] == order.component[b],
                        "case {case}: {a} {b}"
                    );
                }
            }
            assert_eq!(
                order,
                callee_first_order(nodes, |item| graph[item].iter().copied()),
                "case {case}: deterministic"
            );
        }
    }

    #[test]
    fn callee_first_order_survives_a_very_deep_call_chain() {
        let len = 100_000;
        let order = callee_first_order(len, |item| (item + 1 < len).then_some(item + 1));
        assert_eq!(order.order[0], len - 1);
        assert_eq!(order.level[0], len - 1);
    }

    #[test]
    fn waves_run_level_by_level_and_repeat_a_recursive_level() {
        let graph = [vec![1, 2], vec![2], vec![1, 3], vec![3], vec![]];
        let order = callee_first_order(graph.len(), |item| graph[item].iter().copied());
        let mut waves = WaveWorklist::new(&order);
        assert_eq!(waves.pop_wave(), Some(vec![3, 4]));
        // 3 changed; its readers are itself (level 0) and 2 (level 1).
        waves.mark_dirty(3);
        waves.mark_dirty(2);
        assert_eq!(waves.pop_wave(), Some(vec![3]), "level 0 again first");
        assert_eq!(waves.pop_wave(), Some(vec![1, 2]));
        // 1 changed inside the 1 <-> 2 cycle.
        waves.mark_dirty(2);
        waves.mark_dirty(0);
        assert_eq!(waves.pop_wave(), Some(vec![2]));
        assert_eq!(waves.pop_wave(), Some(vec![0]));
        assert_eq!(waves.pop_wave(), None);
        assert_eq!(waves.evaluations(), 7);
    }

    #[test]
    fn dependents_replace_previous_reads() {
        let mut dependents = Dependents::new(4);
        dependents.record(0, [1, 2, 2, 9]);
        dependents.record(3, [1]);
        assert_eq!(dependents.readers(1).collect::<Vec<_>>(), vec![0, 3]);
        assert_eq!(dependents.readers(2).collect::<Vec<_>>(), vec![0]);
        dependents.record(0, [3]);
        assert_eq!(dependents.readers(1).collect::<Vec<_>>(), vec![3]);
        assert!(dependents.readers(2).next().is_none());
        assert_eq!(dependents.readers(3).collect::<Vec<_>>(), vec![0]);
        assert!(dependents.readers(7).next().is_none());
        dependents.record(8, [0]);
    }

    #[test]
    fn joins_report_growth_only() {
        let mut set = BTreeSet::from([1, 2]);
        assert!(!join_set(&mut set, BTreeSet::from([2])));
        assert!(join_set(&mut set, BTreeSet::from([3])));
        let mut map = BTreeMap::from([("a", BTreeSet::from([1]))]);
        assert!(!join_map(
            &mut map,
            BTreeMap::from([("a", BTreeSet::from([1]))])
        ));
        assert!(join_map(
            &mut map,
            BTreeMap::from([("a", BTreeSet::from([2]))])
        ));
        assert!(join_map(&mut map, BTreeMap::from([("b", BTreeSet::new())])));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn keyed_tables_answer_through_either_view() {
        fn read(table: &impl KeyedTable<u8>) -> Option<u8> {
            table.lookup("k").copied()
        }
        let table = BTreeMap::from([("k".to_string(), 7u8)]);
        let index = HashMap::from([("k".to_string(), 0)]);
        assert_eq!(read(&table), Some(7));
        let view = TrackedReads::new(&table, &index);
        assert_eq!(read(&view), Some(7));
        assert_eq!(view.into_reads(), vec![0]);
    }

    #[test]
    fn tracked_reads_record_only_tracked_rows() {
        let table = BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2)]);
        let index = HashMap::from([("a".to_string(), 0), ("b".to_string(), 1)]);
        let view = TrackedReads::new(&table, &index);
        assert_eq!(view.get("b"), Some(&2));
        assert_eq!(view.get("missing"), None);
        assert_eq!(view.get("a"), Some(&1));
        assert_eq!(view.into_reads(), vec![1, 0]);
    }
}
