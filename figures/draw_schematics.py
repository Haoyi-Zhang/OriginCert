"""Draw the manuscript schematics directly as font-embedded vector PDFs.

Run: python figures/draw_schematics.py --output figures
Requires Python 3.9+ and Matplotlib. No TeX engine or network is used.
The diagrams express the defined model; they are not measurement plots.
"""
import argparse
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle, Polygon, Circle, FancyArrowPatch

plt.rcParams.update({'font.family':'STIXGeneral', 'mathtext.fontset':'stix',
                     'font.size':9, 'pdf.fonttype':42, 'ps.fonttype':42,
                     'text.usetex':False, 'axes.unicode_minus':False})
CM = 1 / 2.54

class Drawing:
    def __init__(self, bounds):
        x0,y0,x1,y1 = bounds
        self.fig = plt.figure(figsize=((x1-x0)*CM,(y1-y0)*CM))
        self.ax = self.fig.add_axes([0,0,1,1], xlim=(x0,x1), ylim=(y0,y1))
        self.ax.set_aspect('equal'); self.ax.axis('off')
        self.nodes = {}
        self.labels = []

    def text(self,x,y,label,size=9,ha='center',va='center'):
        artist=self.ax.text(x,y,label,fontsize=size,ha=ha,va=va,
                            linespacing=1.15,clip_on=False,zorder=4)
        self.labels.append([artist,None])
        return artist

    def box(self,name,x,y,w,h,label,dashed=False,shape='rect',size=9):
        style = {'edgecolor':'black','facecolor':'white','linewidth':.55,
                 'linestyle':(0,(4,3)) if dashed else 'solid', 'zorder':2}
        if shape == 'diamond':
            obj = Polygon([(x-w/2,y),(x,y+h/2),(x+w/2,y),(x,y-h/2)],**style)
        elif shape == 'circle': obj = Circle((x,y),w/2,**style)
        else: obj = Rectangle((x-w/2,y-h/2),w,h,**style)
        self.ax.add_patch(obj); self.text(x,y,label,size)
        self.labels[-1][1]=(x-w/2,y-h/2,x+w/2,y+h/2)
        self.nodes[name] = (x,y,w,h,shape)

    def point(self,name,side):
        x,y,w,h,_ = self.nodes[name]
        return {'n':(x,y+h/2),'s':(x,y-h/2),'e':(x+w/2,y),
                'w':(x-w/2,y),'nw':(x-w/2,y+h/2),
                'ne':(x+w/2,y+h/2),'c':(x,y)}[side]

    def line(self,points,dashed=False):
        xs,ys=zip(*points)
        self.ax.plot(xs,ys,color='black',linewidth=.55,
                     linestyle=(0,(4,3)) if dashed else 'solid',zorder=1)

    def arrow(self,p,q,dashed=False,via=()):
        points=[p,*via,q]
        if via:self.line(points[:-1],dashed)
        self.ax.add_patch(FancyArrowPatch(points[-2],points[-1],
                         arrowstyle='-|>',mutation_scale=7.5,linewidth=.55,
                         color='black',shrinkA=0,shrinkB=0,
                         linestyle=(0,(4,3)) if dashed else 'solid',zorder=1))

    def edge(self,a,b,sa='s',sb='n',**kwargs):
        self.arrow(self.point(a,sa),self.point(b,sb),**kwargs)

    def frame(self,x,y,w,h):
        self.ax.add_patch(Rectangle((x,y),w,h,fill=False,edgecolor='black',
                                   linewidth=.55,linestyle=(0,(4,3)),zorder=0))

    def save(self,out,name):
        # Fixed physical canvas: do not enlarge or rasterize the scientific figure.
        self.fig.canvas.draw()
        renderer=self.fig.canvas.get_renderer()
        x0,x1=self.ax.get_xlim();y0,y1=self.ax.get_ylim()
        for artist,node in self.labels:
            b=artist.get_window_extent(renderer).transformed(self.ax.transData.inverted())
            if b.x0<x0-.02 or b.x1>x1+.02 or b.y0<y0-.02 or b.y1>y1+.02:
                raise ValueError(name+': clipped label '+repr(artist.get_text()))
            if node and (b.x0<node[0]-.02 or b.x1>node[2]+.02 or b.y0<node[1]-.02 or b.y1>node[3]+.02):
                raise ValueError(name+': label exceeds node '+repr(artist.get_text()))
        self.fig.savefig(out/(name+'.pdf'),format='pdf',
                         metadata={'Creator':'Python Matplotlib','Producer':None,
                                   'CreationDate':None,'ModDate':None})
        plt.close(self.fig)




def draw(out):
    d=Drawing((-2,-8.15,6.6,1.2))
    for key,x,y,label in [('s',0,0,'sanitize($q$)\norigin $n_1$'),
                          ('q',0,-2.1,'query($q$)\norigin $n_2$'),
                          ('es',4.6,0,'protect $q$\n{SQL-sanitize}'),
                          ('eq',4.6,-2.1,'DB query $q$\nobligation CWE-89'),
                          ('cs',0,-4.7,'protect $q$'),
                          ('cq',0,-6.8,'DB query $q$\nobligation $\\varnothing$'),
                          ('os',4.6,-4.7,'protect $q$'),
                          ('oq',4.6,-6.8,'DB query $q$\norigin $n_{404}$')]:d.box(key,x,y,3,1.1,label)
    for top,bottom in [('s','q'),('es','eq'),('cs','cq'),('os','oq')]:d.edge(top,bottom)
    for x,y,label in [(0,1.0,'Generator branch'),(4.6,1.0,'Certified trace'),
                       (0,-3.7,'Same safe operations'),(4.6,-3.7,'Same safe operations')]:d.text(x,y,label)
    d.frame(-1.7,-7.55,3.4,1.5);d.frame(2.9,-7.55,3.4,1.5)
    d.text(0,-7.95,'coverage fault',size=8.5);d.text(4.6,-7.95,'origin fault',size=8.5)
    d.save(out,'motivating')

    # Twelve assignments, four non-overlapping Cartesian cells, three traces.
    d=Drawing((-2.55,-1.72,8.05,2.32))
    d.text(-1.4,2.1,'field $a$');d.text(-2.12,.45,'field $b$').set_rotation(90)
    for x in range(4):
        d.text(-.9+1.35*x,1.78,'$a_'+str(x)+'$')
        for y in range(3):d.box('c'+str(x)+str(y),-.9+1.35*x,1-1.05*y,1.2,.9,'')
    for y in range(3):d.text(-1.78,1-1.05*y,'$b_'+str(y)+'$')
    for xmin,ymin,xmax,ymax in [(-1.52,-.52,1.07,1.47),(1.18,.53,3.77,1.47),
                               (-1.52,-1.57,1.07,-.63),(1.18,-1.57,3.77,.42)]:
        d.ax.add_patch(Rectangle((xmin,ymin),xmax-xmin,ymax-ymin,fill=False,edgecolor='black',linewidth=1.3,zorder=3))
    for x,y,t in [(-.9,1,1),(1.8,1,2),(-.9,-1.1,3),(1.8,-.05,3)]:d.text(x,y,'$t_'+str(t)+'$')
    d.text(6.1,-1.1,'Twelve assignments\nform four cells\nfor three traces')
    d.arrow((3.75,-1.1),(4.75,-1.1))
    d.save(out,'partition')

    d=Drawing((-1.4,-2.2,12.5,2.2))
    d.box('input',0,0,2.3,1.2,'Generator\nschema\ncatalogue')
    d.box('producer',2.8,0,1.9,1.15,'Symbolic\nproducer')
    d.box('decision',5.25,0,1.9,1.15,'All cells\nsafe?')
    d.box('cert',8.2,1.2,2.7,1.7,'Certificate\ncells and traces\norigins and\nobligations')
    d.box('cex',8.2,-1.2,2.7,1.7,'Counterexample\nminimum input\nfirst bad prefix')
    d.box('checker',11.1,0,2.2,2.4,'Independent\nchecker\nregions /\nwitness replay')
    d.edge('input','producer','e','w');d.edge('producer','decision','e','w')
    d.edge('decision','cert','e','w');d.edge('decision','cex','e','w')
    d.text(6.4,.75,'yes');d.text(6.4,-.75,'no')
    d.arrow(d.point('cert','e'),(10,1.2));d.arrow(d.point('cex','e'),(10,-1.2))
    d.save(out,'pipeline')

    d=Drawing((-1.6,-2.85,11.2,.8))
    for key,x,label in [('pre',0,'Pre-state\n$\\sigma_j$'),
                         ('check',3.2,'Origin, coverage\nand rule checks'),
                         ('update',6.4,'Always apply\n$\\delta(\\sigma_j,e_j)$'),
                         ('post',9.6,'Post-state\n$\\sigma_{j+1}$')]:d.box(key,x,0,2.7,1.2,label)
    d.box('fail',3.2,-2.1,2.7,1.2,'Append violations\nnever erase them')
    d.edge('pre','check','e','w');d.edge('check','update','e','w');d.edge('update','post','e','w');d.edge('check','fail')
    d.save(out,'monitor-step')

    d=Drawing((-1.7,-3.4,9.7,.8))
    d.box('g',0,0,2.8,1.3,'Serialized subject\n$S,G,\\mathcal{O}$')
    d.box('t',4,0,2.8,1.3,'Certified event\nrelation $d\\mapsto t_d$')
    d.box('s',8,0,2.8,1.3,'Reference source\n$L_b(t_d)$')
    d.box('e',8,-2.6,2.8,1.3,'Paired decoder\n$E_b(L_b(t_d))$')
    d.box('v',0,-2.6,2.8,1.3,'Vendor frontend,\nruntime and build',dashed=True)
    d.edge('g','t','e','w');d.edge('t','s','e','w');d.edge('s','e')
    d.edge('e','t','w','s',via=((4,-2.6),))
    d.text(3.8,-1.55,'exact event\nequality',ha='right',size=8.5)
    d.line([d.point('v','n'),d.point('g','s')],dashed=True)
    d.text(.18,-1.3,'not established',ha='left')
    d.save(out,'concrete-boundary')

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,default=Path(__file__).resolve().parent)
    output=parser.parse_args().output
    output.mkdir(parents=True,exist_ok=True)
    draw(output)
