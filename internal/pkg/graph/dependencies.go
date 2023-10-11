// // // // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// // // // SPDX-License-Identifier: Apache-2.0

// // // // Package graph provides functionality for directed graphs.
package graph

// import (
// 	"context"
// 	"fmt"
// 	"slices"
// 	"strings"
// 	"sync"

// 	"github.com/aws/copilot-cli/internal/pkg/term/log"
// 	"golang.org/x/sync/errgroup"
// )

// // ContainerStatus indicates the status of a Container
// type ContainerStatus int

// // Containers status flags
// const (
// 	ContainerStopped ContainerStatus = iota
// 	ContainerStarted
// 	ContainerComplete
// 	ContainerHealthy
// )

// type Graph1Traversal struct {
// 	mu      sync.Mutex
// 	seen    map[string]struct{}
// 	ignored map[string]struct{}

// 	extremityNodesFn              func(*Graph1) []*Vertex                          // leaves or roots
// 	adjacentNodesFn               func(*Vertex) []*Vertex                          // getParents or getChildren
// 	filterAdjacentByStatusFn      func(*Graph1, string, ContainerStatus) []*Vertex // filterChildren or filterParents
// 	targetContainerStatus         ContainerStatus
// 	adjacentContainerStatusToSkip ContainerStatus

// 	visitorFn func(context.Context, string) error
// }

// func upDirectionTraversal(visitorFn func(context.Context, string) error) *Graph1Traversal {
// 	return &Graph1Traversal{
// 		extremityNodesFn:              leaves,
// 		adjacentNodesFn:               getParents,
// 		filterAdjacentByStatusFn:      filterChildren,
// 		adjacentContainerStatusToSkip: ContainerStopped,
// 		targetContainerStatus:         ContainerStarted,
// 		visitorFn:                     visitorFn,
// 	}
// }

// func downDirectionTraversal(visitorFn func(context.Context, string) error) *Graph1Traversal {
// 	return &Graph1Traversal{
// 		extremityNodesFn:              roots,
// 		adjacentNodesFn:               getChildren,
// 		filterAdjacentByStatusFn:      filterParents,
// 		adjacentContainerStatusToSkip: ContainerStarted,
// 		targetContainerStatus:         ContainerStopped,
// 		visitorFn:                     visitorFn,
// 	}
// }

// type ContainerDependency struct {
// 	Essential bool
// 	DependsOn
// }

// type DependsOn map[string]string

// // InDependencyOrder applies the function to the Containers of the project taking in account the dependency order
// func InDependencyOrder(ctx context.Context, containers map[string]ContainerDependency, fn func(context.Context, string) error, options ...func(*Graph1Traversal)) error {
// 	Graph1, err := NewGraph1(containers, ContainerStopped)
// 	if err != nil {
// 		return err
// 	}
// 	t := upDirectionTraversal(fn)
// 	for _, option := range options {
// 		option(t)
// 	}
// 	return t.visit(ctx, Graph1)
// }

// // InReverseDependencyOrder applies the function to the Containers of the project in reverse order of dependencies
// func InReverseDependencyOrder(ctx context.Context, containers map[string]ContainerDependency, fn func(context.Context, string) error, options ...func(*Graph1Traversal)) error {
// 	Graph1, err := NewGraph1(containers, ContainerStarted)
// 	if err != nil {
// 		return err
// 	}
// 	for k, v := range Graph1.Vertices {
// 		log.Infoln("%s%s", k, v.Container, v.Children, v.Parents, v.Status, v.Key)
// 	}
// 	t := downDirectionTraversal(fn)
// 	for _, option := range options {
// 		option(t)
// 	}
// 	return t.visit(ctx, Graph1)
// }

// func WithRootNodesAndDown(nodes []string) func(*Graph1Traversal) {
// 	return func(t *Graph1Traversal) {
// 		if len(nodes) == 0 {
// 			return
// 		}
// 		originalFn := t.extremityNodesFn
// 		t.extremityNodesFn = func(Graph1 *Graph1) []*Vertex {
// 			var want []string
// 			for _, node := range nodes {
// 				vertex := Graph1.Vertices[node]
// 				want = append(want, vertex.Container)
// 				for _, v := range getAncestors(vertex) {
// 					want = append(want, v.Container)
// 				}
// 			}

// 			t.ignored = map[string]struct{}{}
// 			for k := range Graph1.Vertices {
// 				if !slices.Contains(want, k) {
// 					t.ignored[k] = struct{}{}
// 				}
// 			}

// 			return originalFn(Graph1)
// 		}
// 	}
// }

// func (t *Graph1Traversal) visit(ctx context.Context, g *Graph1) error {
// 	expect := len(g.Vertices)
// 	if expect == 0 {
// 		return nil
// 	}

// 	eg, ctx := errgroup.WithContext(ctx)
// 	nodeCh := make(chan *Vertex, expect)
// 	defer close(nodeCh)
// 	// nodeCh need to allow n=expect writers while reader goroutine could have returner after ctx.Done
// 	eg.Go(func() error {
// 		for {
// 			select {
// 			case <-ctx.Done():
// 				return nil
// 			case node := <-nodeCh:
// 				expect--
// 				if expect == 0 {
// 					return nil
// 				}
// 				t.run(ctx, g, eg, t.adjacentNodesFn(node), nodeCh)
// 			}
// 		}
// 	})

// 	nodes := t.extremityNodesFn(g)
// 	t.run(ctx, g, eg, nodes, nodeCh)
// 	return eg.Wait()
// }

// // Note: this could be `Graph1.walk` or whatever
// func (t *Graph1Traversal) run(ctx context.Context, Graph1 *Graph1, eg *errgroup.Group, nodes []*Vertex, nodeCh chan *Vertex) {
// 	for _, node := range nodes {
// 		// Don't start this Container yet if all of its children have
// 		// not been started yet.
// 		if len(t.filterAdjacentByStatusFn(Graph1, node.Key, t.adjacentContainerStatusToSkip)) != 0 {
// 			continue
// 		}

// 		node := node
// 		if !t.consume(node.Key) {
// 			// another worker already visited this node
// 			continue
// 		}

// 		eg.Go(func() error {
// 			var err error
// 			if _, ignore := t.ignored[node.Container]; !ignore {
// 				err = t.visitorFn(ctx, node.Container)
// 			}
// 			if err == nil {
// 				Graph1.UpdateStatus(node.Key, t.targetContainerStatus)
// 			}
// 			nodeCh <- node
// 			return err
// 		})
// 	}
// }

// func (t *Graph1Traversal) consume(nodeKey string) bool {
// 	t.mu.Lock()
// 	defer t.mu.Unlock()
// 	if t.seen == nil {
// 		t.seen = make(map[string]struct{})
// 	}
// 	if _, ok := t.seen[nodeKey]; ok {
// 		return false
// 	}
// 	t.seen[nodeKey] = struct{}{}
// 	return true
// }

// // Graph1 represents project as Container dependencies
// type Graph1 struct {
// 	Vertices map[string]*Vertex
// 	lock     sync.RWMutex
// }

// // Vertex represents a Container in the dependencies structure
// type Vertex struct {
// 	Key       string
// 	Container string
// 	Status    ContainerStatus
// 	Children  map[string]*Vertex
// 	Parents   map[string]*Vertex
// }

// func getParents(v *Vertex) []*Vertex {
// 	return v.GetParents()
// }

// // GetParents returns a slice with the parent vertices of the a Vertex
// func (v *Vertex) GetParents() []*Vertex {
// 	var res []*Vertex
// 	for _, p := range v.Parents {
// 		res = append(res, p)
// 	}
// 	return res
// }

// func getChildren(v *Vertex) []*Vertex {
// 	return v.GetChildren()
// }

// // getAncestors return all descendents for a vertex, might contain duplicates
// func getAncestors(v *Vertex) []*Vertex {
// 	var descendents []*Vertex
// 	for _, parent := range v.GetParents() {
// 		descendents = append(descendents, parent)
// 		descendents = append(descendents, getAncestors(parent)...)
// 	}
// 	return descendents
// }

// // GetChildren returns a slice with the child vertices of the a Vertex
// func (v *Vertex) GetChildren() []*Vertex {
// 	var res []*Vertex
// 	for _, p := range v.Children {
// 		res = append(res, p)
// 	}
// 	return res
// }

// // NewGraph1 returns the dependency Graph1 of the Containers
// func NewGraph1(containers map[string]ContainerDependency, initialStatus ContainerStatus) (*Graph1, error) {
// 	Graph1 := &Graph1{
// 		lock:     sync.RWMutex{},
// 		Vertices: map[string]*Vertex{},
// 	}

// 	for name := range containers {
// 		Graph1.AddVertex(name, name, initialStatus)
// 	}
// 	for name, dep := range containers {
// 		for depName := range dep.DependsOn {
// 			Graph1.AddEdge(name, depName)
// 		}
// 	}

// 	if b, err := Graph1.HasCycles(); b {
// 		return nil, err
// 	}

// 	return Graph1, nil
// }

// // NewVertex is the constructor function for the Vertex
// func NewVertex(key string, Container string, initialStatus ContainerStatus) *Vertex {
// 	return &Vertex{
// 		Key:       key,
// 		Container: Container,
// 		Status:    initialStatus,
// 		Parents:   map[string]*Vertex{},
// 		Children:  map[string]*Vertex{},
// 	}
// }

// // AddVertex adds a vertex to the Graph1
// func (g *Graph1) AddVertex(key string, Container string, initialStatus ContainerStatus) {
// 	g.lock.Lock()
// 	defer g.lock.Unlock()

// 	v := NewVertex(key, Container, initialStatus)
// 	g.Vertices[key] = v
// }

// // AddEdge adds a relationship of dependency between vertices `source` and `destination`
// func (g *Graph1) AddEdge(source, destination string) {
// 	g.lock.Lock()
// 	defer g.lock.Unlock()

// 	sourceVertex := g.Vertices[source]
// 	destinationVertex := g.Vertices[destination]

// 	// If they are already connected
// 	if _, ok := sourceVertex.Children[destination]; ok {
// 		return
// 	}
// 	if sourceVertex != nil {
// 		sourceVertex.Children[destination] = destinationVertex
// 	}
// 	if destinationVertex != nil {
// 		destinationVertex.Parents[source] = sourceVertex
// 	}

// 	return
// }

// func leaves(g *Graph1) []*Vertex {
// 	return g.Leaves()
// }

// // Leaves returns the slice of leaves of the Graph1
// func (g *Graph1) Leaves() []*Vertex {
// 	g.lock.Lock()
// 	defer g.lock.Unlock()

// 	var res []*Vertex
// 	for _, v := range g.Vertices {
// 		if len(v.Children) == 0 {
// 			res = append(res, v)
// 		}
// 	}

// 	return res
// }

// func roots(g *Graph1) []*Vertex {
// 	return g.Roots()
// }

// // Roots returns the slice of "Roots" of the Graph1
// func (g *Graph1) Roots() []*Vertex {
// 	g.lock.Lock()
// 	defer g.lock.Unlock()

// 	var res []*Vertex
// 	for _, v := range g.Vertices {
// 		if len(v.Parents) == 0 {
// 			res = append(res, v)
// 		}
// 	}
// 	return res
// }

// // UpdateStatus updates the status of a certain vertex
// func (g *Graph1) UpdateStatus(key string, status ContainerStatus) {
// 	g.lock.Lock()
// 	defer g.lock.Unlock()
// 	g.Vertices[key].Status = status
// }

// func filterChildren(g *Graph1, k string, s ContainerStatus) []*Vertex {
// 	return g.FilterChildren(k, s)
// }

// // FilterChildren returns children of a certain vertex that are in a certain status
// func (g *Graph1) FilterChildren(key string, status ContainerStatus) []*Vertex {
// 	g.lock.Lock()
// 	defer g.lock.Unlock()

// 	var res []*Vertex
// 	vertex := g.Vertices[key]

// 	for _, child := range vertex.Children {
// 		if child.Status == status {
// 			res = append(res, child)
// 		}
// 	}

// 	return res
// }

// func filterParents(g *Graph1, k string, s ContainerStatus) []*Vertex {
// 	return g.FilterParents(k, s)
// }

// // FilterParents returns the parents of a certain vertex that are in a certain status
// func (g *Graph1) FilterParents(key string, status ContainerStatus) []*Vertex {
// 	g.lock.Lock()
// 	defer g.lock.Unlock()

// 	var res []*Vertex
// 	vertex := g.Vertices[key]

// 	for _, parent := range vertex.Parents {
// 		if parent.Status == status {
// 			res = append(res, parent)
// 		}
// 	}

// 	return res
// }

// // HasCycles detects cycles in the Graph1
// func (g *Graph1) HasCycles() (bool, error) {
// 	discovered := []string{}
// 	finished := []string{}

// 	for _, vertex := range g.Vertices {
// 		path := []string{
// 			vertex.Key,
// 		}
// 		if slices.Contains(discovered, vertex.Key) && !slices.Contains(finished, vertex.Key) {
// 			var err error
// 			discovered, finished, err = g.visit(vertex.Key, path, discovered, finished)

// 			if err != nil {
// 				return true, err
// 			}
// 		}
// 	}

// 	return false, nil
// }

// func (g *Graph1) visit(key string, path []string, discovered []string, finished []string) ([]string, []string, error) {
// 	discovered = append(discovered, key)

// 	for _, v := range g.Vertices[key].Children {
// 		path := append(path, v.Key)
// 		if slices.Contains(discovered, v.Key) {
// 			return nil, nil, fmt.Errorf("cycle found: %s", strings.Join(path, " -> "))
// 		}

// 		if !slices.Contains(finished, v.Key) {
// 			if _, _, err := g.visit(v.Key, path, discovered, finished); err != nil {
// 				return nil, nil, err
// 			}
// 		}
// 	}

// 	discovered = remove(discovered, key)
// 	finished = append(finished, key)
// 	return discovered, finished, nil
// }

// func remove(slice []string, item string) []string {
// 	var s []string
// 	for _, i := range slice {
// 		if i != item {
// 			s = append(s, i)
// 		}
// 	}
// 	return s
// }
