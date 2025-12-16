package command

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type Command struct {
	parent   *Command
	children []*Command
	Name     string
	Summary  string
	Run      func(*Command, []string) error
	PreRun   func(*Command) error
	FlagSet  *flag.FlagSet
	pFlagSet *flag.FlagSet
}

func (c *Command) Args() []string {
	if c.parent == nil {
		return os.Args[1:]
	}
	return c.parent.FlagSet.Args()[1:]
}

func (c *Command) Usage() {
	c.Flags().SetOutput(nil)
	defer func() { c.Flags().SetOutput(io.Discard) }()

	fmt.Fprintf(c.Flags().Output(), "Usage of %q\n", c.Flags().Name())

	c.Flags().VisitAll(func(f *flag.Flag) {
		var b strings.Builder
		if len(f.Name) == 1 {
			fmt.Fprintf(&b, "  -%s", f.Name) // Two spaces before -; see next two comments.
		} else {
			fmt.Fprintf(&b, "  --%s", f.Name) // Two spaces before -; see next two comments.
		}
		name, usage := flag.UnquoteUsage(f)
		if len(name) > 0 {
			b.WriteString(" ")
			b.WriteString(name)
		}
		// Boolean flags of one ASCII letter are so common we
		// treat them specially, putting their usage on the same line.
		if b.Len() <= 4 { // space, space, '-', 'x'.
			b.WriteString("\t")
		} else {
			// Four spaces before the tab triggers good alignment
			// for both 4- and 8-space tab stops.
			b.WriteString("\n    \t")
		}
		b.WriteString(strings.ReplaceAll(usage, "\n", "\n    \t"))
		fmt.Fprint(c.Flags().Output(), b.String(), "\n")
	})

	if len(c.children) <= 0 {
		return
	}

	fmt.Fprintln(c.Flags().Output(), "Sub-commands:")
	for _, chi := range c.children {
		fmt.Fprintf(c.Flags().Output(), "  %s", chi.Name)
		if chi.Summary != "" {
			fmt.Fprintf(c.Flags().Output(), "\n    \t %s", chi.Summary)
		}
		fmt.Fprintln(c.Flags().Output())
	}
}

func (c *Command) Execute() error {
	f := c.Args()

	if err := c.Flags().Parse(f); err != nil {
		if err == flag.ErrHelp {
			c.Usage()
			return nil
		}
		return err
	}

	if c.PreRun != nil {
		if err := c.PreRun(c); err != nil {
			return err
		}
	}

	if c.Run != nil {
		return c.Run(c, c.Flags().Args())
	}

	if len(c.children) > 0 {
		for _, chi := range c.children {
			if chi.CanonicalName() == c.FlagSet.Arg(0) {
				return chi.Execute()
			}
		}
	}
	c.Usage()
	return nil
}
func (c *Command) PersistentFlags() *flag.FlagSet {
	if c.pFlagSet == nil {
		c.pFlagSet = flag.NewFlagSet(c.CanonicalName(), flag.ContinueOnError)
		c.pFlagSet.SetOutput(io.Discard)
	}
	return c.pFlagSet
}

func (c *Command) CanonicalName() string {
	return strings.Split(c.Name, " ")[0]
}

func (c *Command) IsFlagPresent(flagname string) (present bool) {
	c.Flags().Visit(func(f *flag.Flag) {
		if f.Name == flagname {
			present = true
		}
	})
	return
}
func (c *Command) Flags() *flag.FlagSet {
	if c.FlagSet == nil {
		c.FlagSet = flag.NewFlagSet(c.CanonicalName(), flag.ContinueOnError)
		c.FlagSet.SetOutput(io.Discard)
	}

	c.PersistentFlags().VisitAll(func(f *flag.Flag) {
		if ok := c.FlagSet.Lookup(f.Name); ok == nil {
			c.FlagSet.Var(f.Value, f.Name, f.Usage)
		}
	})

	if c.parent != nil {
		c.parent.PersistentFlags().VisitAll(func(f *flag.Flag) {
			if ok := c.FlagSet.Lookup(f.Name); ok == nil {
				c.FlagSet.Var(f.Value, f.Name, f.Usage)
			}
		})
	}
	return c.FlagSet
}

func (c *Command) AddChild(child *Command) {
	child.parent = c
	child.Flags().Init(fmt.Sprintf("%s %s", c.CanonicalName(), child.Name), flag.ContinueOnError)
	child.Flags().SetOutput(io.Discard)
	c.children = append(c.children, child)
}
