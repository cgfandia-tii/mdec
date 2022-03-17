import traceback
from typing import Tuple, Type

import angr
import pyvex
from mdecbase import Service


class FunctionVisitor:
    def __init__(self, project: angr.Project):
        self._project = project

    @classmethod
    def name(cls) -> str:
        raise NotImplementedError()

    @property
    def project(self) -> angr.Project:
        return self._project

    def visit(self, func: angr.knowledge_plugins.functions.Function) -> str:
        raise NotImplementedError()


class DecompilerFunctionVisitor(FunctionVisitor):
    def __init__(self, project: angr.Project):
        super(DecompilerFunctionVisitor, self).__init__(project)

    def name(cls) -> str:
        return 'Decompiler'

    def visit(self, func: angr.knowledge_plugins.functions.Function) -> str:
        dec = self.project.analyses.Decompiler(func)
        return dec.codegen.text if dec.codegen else ''


class IRFunctionVisitor(FunctionVisitor):
    def __init__(self, project: angr.Project):
        super(IRFunctionVisitor, self).__init__(project)

    def name(cls) -> str:
        return 'PyVEX'

    def visit(self, func: angr.knowledge_plugins.functions.Function) -> str:
        func_vex = [f'--- {func.name} ---']
        for block in func.blocks:
            try:
                func_vex.append(
                    str(self.project.factory.block(block.addr).vex))
            except (angr.AngrError, pyvex.PyVEXError):
                func_vex.append(
                    f'/* Producing IR of {block} failed:\n{traceback.format_exc()}\n*/')
        return '\n'.join(func_vex)


class AngrService(Service):
    """
    angr decompiler as a service
    """

    @staticmethod
    def _process_binary(path: str) -> Tuple[angr.Project, angr.analyses.CFG]:
        p = angr.Project(path, auto_load_libs=False, load_debug_info=True)
        cfg = p.analyses.CFG(normalize=True,
                             resolve_indirect_jumps=True,
                             data_references=True,
                             cross_references=True
                             )
        p.analyses.CompleteCallingConventions(
            cfg=cfg,
            recover_variables=True,
            analyze_callsites=True
        )
        return p, cfg

    @staticmethod
    def _process_functions(path: str, visitor_cls: Type[FunctionVisitor]) -> str:
        project, cfg = AngrService._process_binary(path)
        visitor = visitor_cls(project)
        funcs = [func for func in cfg.functions.values()
                 if not func.is_plt
                 and not func.is_simprocedure
                 and not func.alignment
                 ]
        out = []
        for func in funcs:
            try:
                out.append(visitor.visit(func))
            except angr.AngrError:
                out.append(
                    f'/* {visitor_cls.name()} processing {func} failed:\n{traceback.format_exc()}\n*/')

        return '\n'.join(out)

    def decompile(self, path: str) -> str:
        """
        Decompile all the functions in the binary located at `path`.
        """
        return AngrService._process_functions(path, DecompilerFunctionVisitor)

    def ir(self, path: str) -> str:
        """
        Generate VEX IR for all functions in the binary located at `path`.
        """
        return AngrService._process_functions(path, IRFunctionVisitor)

    def version(self) -> str:
        return '.'.join(str(i) for i in angr.__version__)

    def ir_version(self) -> str:
        return '.'.join(str(i) for i in pyvex.__version__)
