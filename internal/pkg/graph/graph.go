// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package graph provides functionality for directed graphs.
package graph

import (
	"context"
	"sync"

	"golang.org/x/sync/errgroup"
)

// vertexStatus denotes the visiting status of a vertex when running DFS in a graph.
type vertexStatus int

const (
	unvisited vertexStatus = iota + 1
	visiting
	visited
)

// Graph represents a directed graph.
type Graph[V comparable] struct {
	vertices  map[V]neighbors[V] // Adjacency list for each vertex.
	inDegrees map[V]int          // Number of incoming edges for each vertex.
	status    map[V]string
	lock      sync.RWMutex
}

// Edge represents one edge of a directed graph.
type Edge[V comparable] struct {
	From V
	To   V
}

type neighbors[V comparable] map[V]bool

// New initiates a new Graph.
func New[V comparable](vertices ...V) *Graph[V] {
	adj := make(map[V]neighbors[V])
	inDegrees := make(map[V]int)
	for _, vertex := range vertices {
		adj[vertex] = make(neighbors[V])
		inDegrees[vertex] = 0
	}
	return &Graph[V]{
		vertices:  adj,
		inDegrees: inDegrees,
	}
}

type GraphOption[V comparable] func(g *Graph[V])

func WithStatus[V comparable](status string) func(g *Graph[V]) {
	return func(g *Graph[V]) {
		g.status = make(map[V]string)
		for vertex := range g.vertices {
			g.status[vertex] = status
		}
	}
}

// Neighbors returns the list of connected vertices from vtx.
func (g *Graph[V]) Neighbors(vtx V) []V {
	g.lock.Lock()
	defer g.lock.Unlock()
	neighbors, ok := g.vertices[vtx]
	if !ok {
		return nil
	}
	arr := make([]V, len(neighbors))
	i := 0
	for neighbor := range neighbors {
		arr[i] = neighbor
		i += 1
	}
	return arr
}

// Add adds a connection between two vertices.
func (g *Graph[V]) Add(edge Edge[V]) {
	g.lock.Lock()
	defer g.lock.Unlock()
	from, to := edge.From, edge.To
	if _, ok := g.vertices[from]; !ok {
		g.vertices[from] = make(neighbors[V])
	}
	if _, ok := g.vertices[to]; !ok {
		g.vertices[to] = make(neighbors[V])
	}
	if _, ok := g.inDegrees[from]; !ok {
		g.inDegrees[from] = 0
	}
	if _, ok := g.inDegrees[to]; !ok {
		g.inDegrees[to] = 0
	}

	g.vertices[from][to] = true
	g.inDegrees[to] += 1
}

// InDegree returns the number of incoming edges to vtx.
func (g *Graph[V]) InDegree(vtx V) int {
	return g.inDegrees[vtx]
}

// Remove deletes a connection between two vertices.
func (g *Graph[V]) Remove(edge Edge[V]) {
	if _, ok := g.vertices[edge.From][edge.To]; !ok {
		return
	}
	delete(g.vertices[edge.From], edge.To)
	g.inDegrees[edge.To] -= 1
}

type findCycleTempVars[V comparable] struct {
	status     map[V]vertexStatus
	parents    map[V]V
	cycleStart V
	cycleEnd   V
}

// IsAcyclic checks if the graph is acyclic. If not, return the first detected cycle.
func (g *Graph[V]) IsAcyclic() ([]V, bool) {
	g.lock.Lock()
	defer g.lock.Unlock()
	var cycle []V
	status := make(map[V]vertexStatus)
	for vertex := range g.vertices {
		status[vertex] = unvisited
	}
	temp := findCycleTempVars[V]{
		status:  status,
		parents: make(map[V]V),
	}
	// We will run a series of DFS in the graph. Initially all vertices are marked unvisited.
	// From each unvisited vertex, start the DFS, mark it visiting while entering and mark it visited on exit.
	// If DFS moves to a visiting vertex, then we have found a cycle. The cycle itself can be reconstructed using parent map.
	// See https://cp-algorithms.com/graph/finding-cycle.html
	for vertex := range g.vertices {
		if status[vertex] == unvisited && g.hasCycles(&temp, vertex) {
			for n := temp.cycleStart; n != temp.cycleEnd; n = temp.parents[n] {
				cycle = append(cycle, n)
			}
			cycle = append(cycle, temp.cycleEnd)
			return cycle, false
		}
	}
	return nil, true
}

// Roots returns a slice of vertices with no incoming edges.
func (g *Graph[V]) Roots() []V {
	var roots []V
	for vtx, degree := range g.inDegrees {
		if degree == 0 {
			roots = append(roots, vtx)
		}
	}
	return roots
}

func (g *Graph[V]) hasCycles(temp *findCycleTempVars[V], currVertex V) bool {
	temp.status[currVertex] = visiting
	for vertex := range g.vertices[currVertex] {
		if temp.status[vertex] == unvisited {
			temp.parents[vertex] = currVertex
			if g.hasCycles(temp, vertex) {
				return true
			}
		} else if temp.status[vertex] == visiting {
			temp.cycleStart = currVertex
			temp.cycleEnd = vertex
			return true
		}
	}
	temp.status[currVertex] = visited
	return false
}

// TopologicalSorter ranks vertices using Kahn's algorithm: https://en.wikipedia.org/wiki/Topological_sorting#Kahn's_algorithm
// However, if two vertices can be scheduled in parallel then the same rank is returned.
type TopologicalSorter[V comparable] struct {
	ranks map[V]int
}

// Rank returns the order of the vertex. The smallest order starts at 0.
// The second boolean return value is used to indicate whether the vertex exists in the graph.
func (alg *TopologicalSorter[V]) Rank(vtx V) (int, bool) {
	r, ok := alg.ranks[vtx]
	return r, ok
}

func (alg *TopologicalSorter[V]) traverse(g *Graph[V]) {
	roots := g.Roots()
	for _, root := range roots {
		alg.ranks[root] = 0 // Explicitly set to 0 so that `_, ok := alg.ranks[vtx]` returns true instead of false.
	}
	for len(roots) > 0 {
		var vtx V
		vtx, roots = roots[0], roots[1:]
		for _, neighbor := range g.Neighbors(vtx) {
			if new, old := alg.ranks[vtx]+1, alg.ranks[neighbor]; new > old {
				alg.ranks[neighbor] = new
			}
			g.Remove(Edge[V]{vtx, neighbor})
			if g.InDegree(neighbor) == 0 {
				roots = append(roots, neighbor)
			}
		}
	}
}

// TopologicalOrder determines whether the directed graph is acyclic, and if so then
// finds a topological-order, or a linear order, of the vertices.
// Note that this function will modify the original graph.
//
// If there is an edge from vertex V to U, then V must happen before U and results in rank of V < rank of U.
// When there are ties (two vertices can be scheduled in parallel), the vertices are given the same rank.
// If the digraph contains a cycle, then an error is returned.
//
// An example graph and their ranks is shown below to illustrate:
// .
// ├── a          rank: 0
// │   ├── c      rank: 1
// │   │   └── f  rank: 2
// │   └── d      rank: 1
// └── b          rank: 0
//
//	└── e      rank: 1
func TopologicalOrder[V comparable](digraph *Graph[V]) (*TopologicalSorter[V], error) {
	if vertices, isAcyclic := digraph.IsAcyclic(); !isAcyclic {
		return nil, &errCycle[V]{
			vertices,
		}
	}

	topo := &TopologicalSorter[V]{
		ranks: make(map[V]int),
	}
	topo.traverse(digraph)
	return topo, nil
}

type ComponentData[V comparable] struct {
	Nodes []V
	Ranks map[V]int
}

func GetConnectedComponentsData[V comparable](g *Graph[V]) []ComponentData[V] {
	visited := make(map[V]bool)
	componentsData := []ComponentData[V]{}

	for v := range g.vertices {
		if !visited[v] {
			componentNodes := []V{}
			dfsCollect(g, v, visited, &componentNodes)

			subGraph := New[V](componentNodes...)
			for _, node := range componentNodes {
				for _, neighbor := range g.Neighbors(node) {
					subGraph.Add(Edge[V]{node, neighbor})
				}
			}

			topoSorter, _ := TopologicalOrder[V](subGraph)
			ranks := make(map[V]int)
			for _, node := range componentNodes {
				rank, _ := topoSorter.Rank(node)
				ranks[node] = rank
			}

			componentsData = append(componentsData, ComponentData[V]{componentNodes, ranks})
		}
	}
	return componentsData
}

func dfsCollect[V comparable](g *Graph[V], v V, visited map[V]bool, nodes *[]V) {
	visited[v] = true
	*nodes = append(*nodes, v)
	for _, neighbor := range g.Neighbors(v) {
		if !visited[neighbor] {
			dfsCollect(g, neighbor, visited, nodes)
		}
	}
}

// InDependencyOrder applies the function to the vertices of the graph taking into account the dependency order.
// The function visits vertices in a topological order based on their dependencies.
func (g *Graph[V]) InDependencyOrder(ctx context.Context, fn func(ctx context.Context, v V) error, adjacentvertexStatusToSkip, targetvertexStatus string, options ...func(*graphTraversal[V])) error {
	t := upDirectionTraversal(fn, adjacentvertexStatusToSkip, targetvertexStatus)
	for _, option := range options {
		option(t)
	}
	// log.Infoln("inital vertre status", g.status)
	return t.visit(ctx, g)
}

func (g *Graph[V]) InReverseDependencyOrder(ctx context.Context, fn func(ctx context.Context, v V) error, adjacentvertexStatusToSkip, targetvertexStatus string, eg *errgroup.Group, options ...func(*graphTraversal[V])) error {
	t := downDirectionTraversal(fn, adjacentvertexStatusToSkip, targetvertexStatus)
	for _, option := range options {
		option(t)
	}
	return t.visit(ctx, g)
}

type graphTraversal[V comparable] struct {
	mu                         sync.RWMutex
	seen                       map[V]struct{}
	ignored                    map[V]struct{}
	extremityvertexsFn         func(*Graph[V]) []V
	adjacentvertexsFn          func(*Graph[V], V) []V
	filterAdjacentFnByStatus   func(*Graph[V], V, string) []V
	targetvertexStatus         string
	adjacentvertexStatusToSkip string
	visitorFn                  func(context.Context, V) error
}

func upDirectionTraversal[V comparable](visitorFn func(context.Context, V) error, adjacentvertexStatusToSkip, targetvertexStatus string) *graphTraversal[V] {
	return &graphTraversal[V]{
		extremityvertexsFn:         func(g *Graph[V]) []V { return g.getLeaves() },
		adjacentvertexsFn:          func(g *Graph[V], vtx V) []V { return getParents(g, vtx) },
		filterAdjacentFnByStatus:   func(g *Graph[V], vtx V, status string) []V { return filterChildren(g, vtx, status) },
		adjacentvertexStatusToSkip: adjacentvertexStatusToSkip,
		targetvertexStatus:         targetvertexStatus,
		visitorFn:                  visitorFn,
	}
}

func downDirectionTraversal[V comparable](visitorFn func(context.Context, V) error, adjacentvertexStatusToSkip, targetvertexStatus string) *graphTraversal[V] {
	return &graphTraversal[V]{
		extremityvertexsFn:         func(g *Graph[V]) []V { return getRoots(g) },
		adjacentvertexsFn:          func(g *Graph[V], vtx V) []V { return getChildren(g, vtx) },
		filterAdjacentFnByStatus:   func(g *Graph[V], vtx V, status string) []V { return filterParents(g, vtx, status) },
		adjacentvertexStatusToSkip: adjacentvertexStatusToSkip,
		targetvertexStatus:         targetvertexStatus,
		visitorFn:                  visitorFn,
	}
}

func (t *graphTraversal[V]) visit(ctx context.Context, graph *Graph[V]) error {
	expect := len(graph.vertices)
	// log.Infoln("len of vertices", expect)
	if expect == 0 {
		return nil
	}

	eg, ctx := errgroup.WithContext(ctx)
	vertexCh := make(chan V, expect)
	defer close(vertexCh)

	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case vertex := <-vertexCh:
				expect--
				if expect == 0 {
					return nil
				}
				adjvertexs := t.adjacentvertexsFn(graph, vertex)
				// log.Infoln("adjvertexs are--->", adjvertexs)
				t.run(ctx, graph, eg, adjvertexs, vertexCh)
			}
		}
	})

	vertices := t.extremityvertexsFn(graph)
	t.run(ctx, graph, eg, vertices, vertexCh)
	return eg.Wait()
}

func (t *graphTraversal[V]) run(ctx context.Context, graph *Graph[V], eg *errgroup.Group, vertices []V, vertexCh chan V) {
	for _, vertex := range vertices {
		// Don't start this vertex yet if all of its children have
		// not been started yet.
		if len(t.filterAdjacentFnByStatus(graph, vertex, t.adjacentvertexStatusToSkip)) != 0 {
			// log.Infoln("all adjacent status passed")
			continue
		}

		vertex := vertex
		if !t.consume(vertex) {
			// log.Infoln("not consumed", vertex)
			// another worker already visited this vertex
			continue
		}

		eg.Go(func() error {
			// var err error
			err := t.visitorFn(ctx, vertex)
			if err != nil {
				return err
			}
			// log.Infoln("error in graph visit", vertex, err)
			// if err == nil {
			// Update the status of the vertex.
			graph.UpdateStatus(vertex, t.targetvertexStatus)
			// }
			// log.Infoln("satisfied vertex", vertex)
			vertexCh <- vertex
			// log.Infoln("all seen vertices", t.seen, graph.status)
			return nil
		})
	}
}

func (t *graphTraversal[V]) consume(vertex V) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen == nil {
		t.seen = make(map[V]struct{})
	}
	if _, ok := t.seen[vertex]; ok {
		return false
	}
	t.seen[vertex] = struct{}{}
	return true
}

// UpdateStatus updates the status of a vertex.
func (g *Graph[V]) UpdateStatus(vertex V, status string) {
	g.lock.Lock()
	defer g.lock.Unlock()
	g.status[vertex] = status
}

// GetStatus gets the status of a vertex.
func (g *Graph[V]) GetStatus(vertex V) string {
	g.lock.Lock()
	defer g.lock.Unlock()
	return g.status[vertex]
}

func (g *Graph[V]) getLeaves() []V {
	g.lock.Lock()
	defer g.lock.Unlock()
	leaves := make([]V, 0)
	for vtx := range g.vertices {
		if len(g.vertices[vtx]) == 0 {
			leaves = append(leaves, vtx)
		}
	}
	return leaves
}

// getParents returns the parent vertices (incoming edges) of vtx.
func getParents[V comparable](g *Graph[V], vtx V) []V {
	g.lock.Lock()
	defer g.lock.Unlock()
	parents := make([]V, 0, g.inDegrees[vtx])
	for v, neighbors := range g.vertices {
		if neighbors[vtx] {
			parents = append(parents, v)
		}
	}
	return parents
}

// getChildren returns the child vertices (outgoing edges) of vtx.
func getChildren[V comparable](g *Graph[V], vtx V) []V {
	return g.Neighbors(vtx)
}

// filterParents filters parents based on the vertex status.
func filterParents[V comparable](g *Graph[V], vtx V, status string) []V {
	parents := getParents(g, vtx)
	filtered := make([]V, 0, len(parents))
	for _, parent := range parents {
		if g.GetStatus(parent) == status {
			filtered = append(filtered, parent)
		}
	}
	return filtered
}

// filterChildren filters children based on the vertex status.
func filterChildren[V comparable](g *Graph[V], vtx V, status string) []V {
	children := getChildren(g, vtx)
	filtered := make([]V, 0, len(children))
	for _, child := range children {
		if g.GetStatus(child) == status {
			filtered = append(filtered, child)
		}
	}
	// log.Infoln("status is", status, len(filtered), children)
	return filtered
}

// getRoots returns the roots (vertices with no incoming edges) in the graph.
func getRoots[V comparable](g *Graph[V]) []V {
	g.lock.Lock()
	defer g.lock.Unlock()
	roots := make([]V, 0)
	for vtx, inDegree := range g.inDegrees {
		if inDegree == 0 {
			roots = append(roots, vtx)
		}
	}
	return roots
}
